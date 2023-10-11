package engine

import (
	"context"

	"github.com/owasp-amass/engine/io"
)

type Handler interface {
	Handle(context.Context, *io.Responses, io.Request) error
}

// Handler Func allows you to wrap Handlers
type HandlerFunc func(context.Context, *io.Responses, io.Request) error

func (f HandlerFunc) Handle(ctx context.Context, resp *io.Responses, req io.Request) error {
	return f(ctx, resp, req)
}

// Something to handle new requests as they come in. Server/Engine?
type Engine interface {
	// Start is a blocking function that receives requests from an input stream, creates a request,
	// and calls Handle() on the passed in Handler.
	Start(Handler) error

	// Stop gracefully stops the Engine
	Stop(context.Context)
}
