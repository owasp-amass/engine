package plugins

import (
	reg "github.com/owasp-amass/engine/registry"
)

type Plugin interface {
	Start(r *reg.Registry) error
	Stop()
}
