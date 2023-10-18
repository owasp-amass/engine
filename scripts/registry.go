package scripts

import (
	"context"
	"fmt"

	"github.com/owasp-amass/engine/io"
	"github.com/owasp-amass/engine/io/infra"
)

type ScriptRegistry struct {
	// event_type -> []func(... responses from collection, request for collection)
	funcs map[string][](func(context.Context, *io.Responses, io.Request) error)
}

func NewRegistry() (*ScriptRegistry, error) {

	registry := &ScriptRegistry{}

	err := registry.loadScripts()
	if err != nil {
		return nil, fmt.Errorf("unable to create script registry: %s", err)
	}

	return registry, nil
}

// Load Scripts reads scripts from the filesystem, parses them, and creates creates a map of supported requests to scripts
func (s *ScriptRegistry) loadScripts() error {

	// likely better ways discovering golang functions that support specific functionality
	// anonymous function used here, but nothing wrong with defining this outside of loadScripts
	gFunc := func(ctx context.Context, resp *io.Responses, req io.Request) error {
		dnsRequest := req.(infra.DNSRequest)

		fmt.Printf("fulfilling DNS request %v", dnsRequest)

		// code for calling out to DNS resolver

		return nil
	}

	// add a function to the registry for the DNS request type
	s.funcs["DNS_REQUEST"] = append(s.funcs["DNS_REQUEST"], gFunc)

	return nil
}

func (s *ScriptRegistry) GetFuncsForType(reqType string) []func(context.Context, *io.Responses, io.Request) error {
	return s.funcs[reqType]
}
