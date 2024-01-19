// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"net/netip"
	"testing"
	"time"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/fingerprint"
	"github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/people"
	oamtls "github.com/owasp-amass/open-asset-model/tls_certificates"
	"github.com/owasp-amass/open-asset-model/url"
	"github.com/owasp-amass/open-asset-model/whois"
)

func TestAddress(t *testing.T) {
	g := NewGraph("memory", "", "")
	defer g.Remove()

	t.Run("Testing UpsertAddress...", func(t *testing.T) {
		want := "192.168.1.1"

		if got, err := g.UpsertAddress(context.Background(), want); err != nil {
			t.Errorf("error inserting address:%v\n", err)
		} else if a, ok := got.Asset.(*network.IPAddress); !ok || a.Address.String() != want {
			t.Error("IP address was not returned properly")
		}
	})

	t.Run("Testing UpsertA...", func(t *testing.T) {
		_, err := g.UpsertA(context.Background(), "owasp.org", "192.168.1.1")
		if err != nil {
			t.Errorf("error inserting fqdn: %v", err)
		}
	})

	t.Run("Testing UpsertAAAA...", func(t *testing.T) {
		_, err := g.UpsertAAAA(context.Background(), "owasp.org", "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
		if err != nil {
			t.Errorf("error inserting AAAA record: %v", err)
		}
	})
}

func TestNameToAddrs(t *testing.T) {
	fqdn := "caffix.net"
	srvfqdn := "inceptions.net"
	addr := "192.168.1.1"

	g := NewGraph("memory", "", "")
	defer g.Remove()

	ctx := context.Background()
	if _, err := g.NamesToAddrs(ctx, time.Time{}, fqdn); err == nil {
		t.Errorf("did not return an error when provided parameters not existing in the graph")
	}

	// test case where cnames and srvs are populated
	_ = createAssets(g.DB)
	if pairs, err := g.NamesToAddrs(ctx, time.Time{}, fqdn, srvfqdn); err != nil {
		t.Errorf("failed to obtain the name / address pairs: %v", err)
	} else if len(pairs) <= 7 {
		t.Errorf("did not obtain the correct number of name / address pairs: %d", len(pairs))
	}

	// test upsert, it should not traverse the cnames and srvs for the fqdn variable
	_, _ = g.UpsertA(ctx, fqdn, addr)
	if pairs, err := g.NamesToAddrs(ctx, time.Time{}, fqdn); err != nil ||
		pairs[0].FQDN.Name != fqdn || pairs[0].Addr.Address.String() != addr {
		t.Errorf("failed to obtain the name / address pairs: %v", err)
	}

	// test non existent domain
	if pairs, err := g.NamesToAddrs(ctx, time.Time{}, "doesnot.exist"); err == nil {
		t.Errorf("did not return an error when provided a name not existing in the graph: %v", pairs)
	}
}

func createAssets(db *assetdb.AssetDB) []*types.Asset {
	// Create test assets
	assets := []oam.Asset{
		&domain.FQDN{Name: "caffix.net"},
		&domain.FQDN{Name: "www.example.com"},
		&domain.FQDN{Name: "www.example.org"},
		&domain.FQDN{Name: "www.example.io"},
		&network.Netblock{Cidr: netip.MustParsePrefix("198.51.100.0/24"), Type: "IPv4"},
		&network.Netblock{Cidr: netip.MustParsePrefix("2001:db8::/32"), Type: "IPv6"},
		&network.IPAddress{Address: netip.MustParseAddr("192.168.1.2"), Type: "IPv4"},
		&network.IPAddress{Address: netip.MustParseAddr("192.168.1.3"), Type: "IPv4"},
		&network.IPAddress{Address: netip.MustParseAddr("192.168.1.4"), Type: "IPv4"},
		&network.IPAddress{Address: netip.MustParseAddr("192.168.1.5"), Type: "IPv4"},
		&network.IPAddress{Address: netip.MustParseAddr("192.168.1.6"), Type: "IPv4"},
		&domain.FQDN{Name: "inceptions.net"},
		&domain.FQDN{Name: "examplesrv.com"},
		&network.IPAddress{Address: netip.MustParseAddr("10.1.20.1"), Type: "IPv4"},
		&network.IPAddress{Address: netip.MustParseAddr("10.1.20.23"), Type: "IPv4"},
		&network.Port{Number: 80, Protocol: "tcp"},
		&network.Port{Number: 443, Protocol: "tcp"},
		&network.RIROrganization{Name: "RIPE NCC"},
		&network.AutonomousSystem{Number: 12345},
		&url.URL{Scheme: "https", Host: "example.com"},
		&org.Organization{OrgName: "Example Inc."},
		&people.Person{FullName: "John Doe"},
		&whois.WHOIS{Domain: "example.com"},
		&whois.Registrar{Name: "Registrar Inc."},
		&contact.EmailAddress{Address: "test@example.com"},
		&contact.Phone{Raw: "+1-555-555-5555"},
		&contact.Location{FormattedAddress: "123 Example St., Example, EX 12345"},
		&oamtls.TLSCertificate{SerialNumber: "1234567890"},
		&fingerprint.Fingerprint{String: "fingerprint"},
	}

	var createdAssets []*types.Asset
	for k, asset := range assets {
		var createdAsset *types.Asset
		var err error

		if _, ok := asset.(*domain.FQDN); ok {

			switch asset.(*domain.FQDN).Name {
			case "caffix.net":
				createdAsset, err = db.Create(nil, "", asset)
			case "inceptions.net":
				createdAsset, err = db.Create(nil, "", asset)
			case "examplesrv.com":
				createdAsset, err = db.Create(createdAssets[11], "srv_record", asset)
			default:
				createdAsset, err = db.Create(createdAssets[k-1], "cname_record", asset)
			}

		} else if _, ok := asset.(*network.IPAddress); ok {

			switch asset.(*network.IPAddress).Address.String() {
			case "10.1.20.1":
				createdAsset, err = db.Create(createdAssets[12], "a_record", asset)
			case "10.1.20.23":
				createdAsset, err = db.Create(createdAssets[12], "srv_record", asset)
			default:
				createdAsset, err = db.Create(createdAssets[3], "a_record", asset)
			}

		} else {
			createdAsset, err = db.Create(nil, "", asset)
		}
		if err != nil {
			panic(err)
		}
		createdAssets = append(createdAssets, createdAsset)
	}
	return createdAssets
}
