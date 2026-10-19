package manager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	decodeProbePageSize = 100
	decodeProbeMaxPages = 50
	decodeProbeTimeout  = 60 * time.Second
)

// schemaMismatchError marks a payload the mirrored Go type cannot decode.
type schemaMismatchError struct {
	gvk schema.GroupVersionKind
	err error
}

func (e *schemaMismatchError) Error() string {
	return fmt.Sprintf("cluster payload for %s does not match the mirrored type: %s", e.gvk, e.err)
}

func (e *schemaMismatchError) Unwrap() error { return e.err }

// probeTypedDecode lists gvk uncached to check the mirrored type decodes what the
// cluster serves. A typed informer that fails its initial LIST never syncs, and
// controller-runtime waits on every informer in the shared cache, so one drifted CRD
// blocks the whole agent. A *schemaMismatchError means skip the controller; any other
// error means the probe could not run and the caller should still create it. It runs
// before mgr.Start against a REST config with no timeout, so a deadline and a page
// budget bound it; exhausting either counts as not having run.
func probeTypedDecode(ctx context.Context, reader client.Reader, scheme *runtime.Scheme, gvk schema.GroupVersionKind) error {
	ctx, cancel := context.WithTimeout(ctx, decodeProbeTimeout)
	defer cancel()

	listGVK := gvk
	listGVK.Kind += "List"

	object, err := scheme.New(listGVK)
	if err != nil {
		return fmt.Errorf("error resolving list type for %s: %w", gvk, err)
	}
	list, ok := object.(client.ObjectList)
	if !ok {
		return fmt.Errorf("%s is registered in the scheme but is not a client.ObjectList", listGVK)
	}

	// Every page has to decode: a clean first page says nothing about the one carrying
	// the drifted field.
	token := ""
	for page := 1; ; page++ {
		if page > decodeProbeMaxPages {
			return fmt.Errorf("gave up probing %s after %d pages", gvk, decodeProbeMaxPages)
		}

		result, ok := list.DeepCopyObject().(client.ObjectList)
		if !ok {
			return fmt.Errorf("deep copy of %s is not a client.ObjectList", listGVK)
		}

		if err := reader.List(ctx, result, client.Limit(decodeProbePageSize), client.Continue(token)); err != nil {
			if probeUnavailable(err) {
				return fmt.Errorf("error listing %s: %w", gvk, err)
			}
			return &schemaMismatchError{gvk: gvk, err: err}
		}

		token = result.GetContinue()
		if token == "" {
			return nil
		}
	}
}

// probeUnavailable reports whether the probe failed to run, rather than the type
// failing to decode a payload the server did return.
func probeUnavailable(err error) bool {
	var status k8serrors.APIStatus
	var netErr net.Error
	var urlErr *url.Error

	return errors.As(err, &status) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.As(err, &netErr) ||
		errors.As(err, &urlErr)
}
