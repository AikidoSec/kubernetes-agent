package batchclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"aikidoSec.kubernetesAgent/internal/services/heartbeat"
	"github.com/go-logr/logr"
)

type ClientOptions struct {
	Endpoint              string
	MaxBatch              int
	FlushEvery            time.Duration
	MaxConcurrentRequests int
	CompressionEnabled    bool
	Token                 string
	HeartbeatService      *heartbeat.Service
}

type BatchClient struct {
	logger logr.Logger
	// target HTTP endpoint
	endpoint string
	// maximum events per batch
	maxBatch int
	// maximum time to wait before flushing a non-full batch
	flushEvery time.Duration
	// if true, enable gzip compression
	compressionEnabled bool
	// semaphore to bound concurrent HTTP sends
	maxConcurrentRequests chan struct{}
	// API token used for authentication
	apiToken         string
	heartbeatService *heartbeat.Service

	httpClient *http.Client
	eventsCh   chan any
	wg         sync.WaitGroup // for run()
	sendWG     sync.WaitGroup // for in-flight sends
	mu         sync.Mutex
	closed     bool
	doneCh     chan struct{} // signal shutdown

	batch []any
}

func NewBatchClient(logger logr.Logger, o ClientOptions) (*BatchClient, error) {
	if o.Endpoint == "" {
		return nil, fmt.Errorf("endpoint value is required")
	}
	if o.MaxBatch <= 0 {
		return nil, fmt.Errorf("maxBatch must be a positive integer")
	}
	if o.FlushEvery <= 0 {
		return nil, fmt.Errorf("flushEvery must be a positive duration")
	}
	if o.MaxConcurrentRequests <= 0 {
		return nil, fmt.Errorf("maxConcurrentRequestsCount must be a positive integer")
	}

	tr := &http.Transport{
		MaxIdleConns:        max(32, o.MaxConcurrentRequests*2),
		MaxIdleConnsPerHost: max(16, o.MaxConcurrentRequests*2),
		IdleConnTimeout:     90 * time.Second,
	}

	bc := &BatchClient{
		logger:                logger,
		heartbeatService:      o.HeartbeatService,
		endpoint:              o.Endpoint,
		apiToken:              o.Token,
		httpClient:            &http.Client{Timeout: 15 * time.Second, Transport: tr},
		maxBatch:              o.MaxBatch,
		flushEvery:            o.FlushEvery,
		batch:                 make([]any, 0, o.MaxBatch),
		eventsCh:              make(chan any, o.MaxBatch*10),
		maxConcurrentRequests: make(chan struct{}, o.MaxConcurrentRequests),
		doneCh:                make(chan struct{}),
		compressionEnabled:    o.CompressionEnabled,
		mu:                    sync.Mutex{},
	}

	bc.wg.Add(1)
	go bc.run()

	return bc, nil
}

func (c *BatchClient) SendContext(ctx context.Context, e any) error {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return context.Canceled
	}
	select {
	case c.eventsCh <- e:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.doneCh:
		return context.Canceled
	}
}

func (c *BatchClient) TrySend(e any) bool {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return false
	}
	select {
	case c.eventsCh <- e:
		return true
	default:
		return false
	}
}

func (c *BatchClient) Close(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.doneCh)
	c.mu.Unlock()

	// wait for run() to exit
	done := make(chan struct{})
	go func() { c.wg.Wait(); close(done) }()

	select {
	case <-done:
		// wait for all in-flight send goroutines
		sendDone := make(chan struct{})
		go func() { c.sendWG.Wait(); close(sendDone) }()
		select {
		case <-sendDone:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *BatchClient) run() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.flushEvery)
	defer ticker.Stop()

	for {
		select {
		case e := <-c.eventsCh:
			c.batch = append(c.batch, e)
			if len(c.batch) >= c.maxBatch {
				c.flush()
			}
		case <-ticker.C:
			c.flush()
		case <-c.doneCh:
			// Close requested -> flush remaining and exit.
			c.flush()
			return
		}
	}
}

func (c *BatchClient) flush() {
	if len(c.batch) == 0 {
		return
	}

	// Copy to avoid races and allow new events to fill the next batch immediately.
	payload := make([]any, len(c.batch))
	copy(payload, c.batch)
	c.batch = c.batch[:0]

	// Acquire a slot before launching the goroutine to avoid unbounded goroutine growth.
	c.maxConcurrentRequests <- struct{}{}
	c.sendWG.Add(1)

	for {
		isServerActive := c.heartbeatService.IsServerActive()
		if isServerActive {
			break
		}

		time.Sleep(c.heartbeatService.GetSendInterval())
	}

	go func() {
		defer func() {
			<-c.maxConcurrentRequests
			c.sendWG.Done()
		}()

		c.send(payload, 1)
	}()
}

func (c *BatchClient) send(events []any, attempt int) {
	c.mu.Lock()
	token := c.apiToken
	c.mu.Unlock()

	// Marshal JSON
	raw, err := json.Marshal(events)
	if err != nil {
		c.logger.Error(err, "error marshaling events")
		return
	}

	var buf bytes.Buffer
	if c.compressionEnabled {
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(raw); err != nil {
			c.logger.Error(err, "error compressing events")
			return
		}
		if err := gz.Close(); err != nil {
			c.logger.Error(err, "error closing gzip writer")
			return
		}
	} else {
		_, err := buf.Write(raw)
		if err != nil {
			c.logger.Error(err, "error writing events to buffer")
			return
		}
	}

	r := bytes.NewReader(buf.Bytes())
	req, err := http.NewRequest(http.MethodPost, c.endpoint, r)
	if err != nil {
		c.logger.Error(err, "error creating request", "endpoint", c.endpoint)
		return
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)

	if c.compressionEnabled {
		req.Header.Set("Content-Encoding", "gzip")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error(err, "error executing request", "endpoint", c.endpoint)
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			c.logger.Error(err, "error closing response body", "endpoint", c.endpoint)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		c.logger.Error(nil, "error executing request", "endpoint", c.endpoint, "statusCode", resp.StatusCode)

		// Exponential backoff with jitter
		d := rand.IntN(max(5, attempt)) * 5
		delay := time.Duration(d) * time.Second
		attempt++

		// If the request failed, we'll retry sending the same batch after a delay until we succeed
		time.Sleep(delay)
		c.send(events, attempt)
	}
}

func (c *BatchClient) SetAPIToken(token string) {
	c.mu.Lock()
	c.apiToken = token
	c.mu.Unlock()
}
