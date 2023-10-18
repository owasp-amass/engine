package mem

import (
	"context"
	"log"
	"time"

	"github.com/owasp-amass/engine"
	"github.com/owasp-amass/engine/io"
)

// DefaultEngine is the default in-memory implementation of the Engine interface.
type Engine struct {
	// C is the channel that buffers requests to be processed by the engine.
	C chan io.Request

	// Future consideration for supporting metric capture.
	// Interested in using OpenTelemetry for metrics.. though this isn't
	// widely adopted yet.

	// maxConcurrentReceives is a buffered channel which acts as
	// a shared lock that limits the number of concurrent goroutines
	maxConcurrentReceives chan struct{}

	listenerCtx        context.Context
	listenerCancelFunc context.CancelFunc

	handlerCtx        context.Context
	handlerCancelFunc context.CancelFunc
}

// NewDefaultEngine initializes a DefaultEngine.
// bufferSize is the size of the channel that buffers requests to be processed by the engine.
// concurrency is the number of concurrent goroutines that can be processing requests.
// RequestDuration is public and should be set on the returned struct using your own metrics provider.
func NewEngine(bufferSize, concurrency int) *Engine {
	if concurrency == 0 {
		concurrency = 1
	}
	if bufferSize == 0 {
		bufferSize = 1
	}

	e := &Engine{
		C:                     make(chan io.Request, bufferSize),
		maxConcurrentReceives: make(chan struct{}, concurrency),
	}

	e.listenerCtx, e.listenerCancelFunc = context.WithCancel(context.Background())
	e.handlerCtx, e.handlerCancelFunc = context.WithCancel(context.Background())

	return e
}

// Start starts the in-memory engine
func (e *Engine) Start(h engine.Handler) error {

	log.Println("Starting engine...")

	for {
		select {
		case <-e.listenerCtx.Done():
			close(e.maxConcurrentReceives)
			// return typed error here?
			return nil
		case req := <-e.C:
			if req == nil {
				continue
			}

			e.maxConcurrentReceives <- struct{}{}

			// each request gets it's own slice of responses
			// resp := make([]io.Response, 0)
			resp := &io.Responses{
				Elems: make([]io.Response, 0),
			}

			// Handle requests that come in through the
			go func(ctx context.Context, resp *io.Responses, req io.Request) {
				defer func() {
					<-e.maxConcurrentReceives
				}()

				// Calls the provided handler (or wrapped handlers)
				err := h.Handle(ctx, resp, req)
				if err != nil {
					log.Println("[ERROR] Error handling request: ", err)
				}
				log.Printf("Request Handled.. resp has %d elements", len(resp.Elems))
				for _, r := range resp.Elems {
					for _, f := range r.RequestFuncs() {
						e.C <- f()
					}
				}

			}(e.handlerCtx, resp, req)
		}
	}
}

// Stop attempts to gracefully stop the Engine.
func (e *Engine) Stop(ctx context.Context) error {
	// Shut down the listener
	e.listenerCancelFunc()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	// handle graceful shutdown of the receiver
	for {
		select {
		case <-ctx.Done():
			// Context canceled, cancel all in-progress handlers
			e.handlerCancelFunc()
			return nil
		case <-ticker.C:
			// All the receivers have finished
			if len(e.maxConcurrentReceives) == 0 {
				return nil
			}
		}
	}

}
