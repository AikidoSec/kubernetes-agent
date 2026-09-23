package predicates

import (
	"bytes"
	"encoding/json"
	"log"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// NewTopLevelFieldsPredicate checks if the object is excluded, the metadata changed or if any of the top level fields changed.
func NewTopLevelFieldsPredicate(nsFilter *NamespaceFilter, fields ...string) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool { return !nsFilter.IsObjectExcluded(e.Object) },
		DeleteFunc: func(e event.DeleteEvent) bool { return !nsFilter.IsObjectExcluded(e.Object) },
		UpdateFunc: func(e event.UpdateEvent) bool {
			if nsFilter.IsObjectExcluded(e.ObjectNew) {
				return false
			}

			if AreAnnotationsChanged(e) || AreLabelsChanged(e) {
				return true
			}

			oldFields, oldErr := objectFields(e.ObjectOld)
			if oldErr != nil {
				log.Printf("error getting old fields: %v", oldErr)
				return false
			}

			newFields, newErr := objectFields(e.ObjectNew)
			if newErr != nil {
				log.Printf("error getting new fields: %v", newErr)
				return false
			}

			for _, field := range fields {
				if !bytes.Equal(oldFields[field], newFields[field]) {
					return true
				}
			}
			return false
		},
	}
}

func objectFields(obj client.Object) (map[string]json.RawMessage, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	err = json.Unmarshal(b, &fields)
	return fields, err
}
