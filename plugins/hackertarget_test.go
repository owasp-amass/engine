package plugins

import (
	"io"
	"log"
	"testing"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/engine"
	"github.com/owasp-amass/engine/types"
	"github.com/owasp-amass/open-asset-model/domain"
)

func TestLookup(t *testing.T) {
	l := log.New(io.Discard, "", log.Lmicroseconds)

	e, err := engine.NewEngine(l)
	if err != nil {
		t.Fatalf("Failed to create a new engine: %v", err)
	}
	defer e.Shutdown()

	// Create a new config
	cfg := config.NewConfig()
	cfg.Scope.Domains = []string{"owasp.org"}

	transSub := config.Transformation{From: "FQDN", To: "ALL"}
	cfg.Transformations["FQDN->ALL"] = &transSub

	transIP := config.Transformation{From: "IPAddress", To: "ALL"}
	cfg.Transformations["IPAddress->ALL"] = &transIP

	// Create a new session
	session, err := e.Manager.NewSession(cfg)
	if err != nil {
		t.Fatalf("Failed to add the session: %v", err)
	}

	now := time.Now()
	fqdn := "owasp.org"
	a := &dbt.Asset{
		CreatedAt: now,
		LastSeen:  now,
		Asset:     &domain.FQDN{Name: fqdn},
	}

	fqdnEvent := types.Event{
		Name:       fqdn,
		Asset:      a,
		Dispatcher: e.Dispatcher,
		Session:    session,
	}

	plugin := &hackerTarget{}
	if err = plugin.lookup(&fqdnEvent); err != nil {
		t.Errorf("LookupDomain failed: %v", err)
	}
}
