package io

import oam "github.com/owasp-amass/open-asset-model"

// Responses wraps a slice of Response elements.
// This allows us to pass responses between handlers using
// the a pointer to an array of interfaces.
type Responses struct {
	Elems []Response
}

// Response represents a response from a data source.
type Response interface {
	// RequestFuncs returns a slice of functions that produce new requests for the engine.
	RequestFuncs() [](func() Request)

	// AssetRelation returns a relation and asset from a response.
	AssetRelation() (string, oam.Asset)

	// Source describes the data source that returned the response, if available.
	Source() string
}
