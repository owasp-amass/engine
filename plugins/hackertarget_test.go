package plugins

import (
	"io"
	"log"
	"testing"

	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/engine"
	"github.com/owasp-amass/engine/sessions"
	"github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
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
	session, err := sessions.NewSession(cfg)
	if err != nil {
		t.Fatalf("Failed to create a new session: %v", err)
	}

	uuid, err := e.Mgr.Add(session)
	if err != nil {
		t.Fatalf("Failed to add the session: %v", err)
	}

	// Create a FQDN event.
	fqdn := "owasp.org"
	fqdnAsset := &types.AssetData{
		OAMAsset: &domain.FQDN{Name: fqdn},
		OAMType:  oam.FQDN,
	}
	fqdnEvent := types.Event{
		SessionID: uuid,
		Data:      fqdnAsset,
		Sched:     e.Sched,
		Session:   session,
	}

	plugin := &hackerTarget{}
	if err = plugin.lookup(&fqdnEvent); err != nil {
		t.Errorf("LookupDomain failed: %v", err)
	}
}
