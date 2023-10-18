package scripts

import (
	"context"
	"log"

	eng "github.com/owasp-amass/engine"
	"github.com/owasp-amass/engine/io"
)

type ScriptHandler struct {
	// Metrics / Tracing / Auditing support
	registry *ScriptRegistry
}

// NewScriptHandler creates a new Handler for
func NewHandler() (*ScriptHandler, error) {
	reg, err := NewRegistry()
	if err != nil {
		log.Println("[ERROR] unable to create script registry: ", err)
		return nil, err
	}
	return &ScriptHandler{
		registry: reg,
	}, nil
}

func (sh *ScriptHandler) Handle(ctx context.Context, resp *io.Responses, req io.Request) error {
	log.Printf("[DEBUG] handling request: %s", req.Type())

	funcs := sh.registry.GetFuncsForType(req.Type())

	for _, f := range funcs {
		if err := f(ctx, resp, req); err != nil {
			return err
		}
	}

	return nil
}

// Execute provides a HandlerFunc for script execution that can wrap other handlers
func (sh *ScriptHandler) Execute(nextHandler eng.Handler) eng.Handler {
	return eng.HandlerFunc(func(ctx context.Context, resp *io.Responses, req io.Request) error {

		funcs := sh.registry.GetFuncsForType(req.Type())

		var agg []io.Response
		for _, f := range funcs {
			if err := f(ctx, resp, req); err != nil {
				log.Println("[ERROR] executing script", err)
				return err
			}
			// aggregate responses here
			agg = append(agg, resp.Elems...)
		}
		resp.Elems = agg

		return nextHandler.Handle(ctx, resp, req)
	})
}
