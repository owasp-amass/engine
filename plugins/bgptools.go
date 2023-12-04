// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	amassnet "github.com/owasp-amass/engine/net"
	"github.com/owasp-amass/engine/registry"
	"github.com/owasp-amass/engine/sessions"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

type bgpTools struct {
	addr string
	port int
}

func newBGPTools() Plugin {
	return &bgpTools{port: 43}
}

func (bt *bgpTools) Start(r *registry.Registry) error {
	rr, err := performQuery("bgp.tools", dns.TypeA)
	if err != nil {
		return fmt.Errorf("failed to obtain the BGPTools IP address: %v", err)
	}
	bt.addr = rr[0].Data

	name := "BGPTools-IP-Handler"
	if err := r.RegisterHandler(&registry.Handler{
		Name:       name,
		Priority:   1,
		Transforms: []string{"netblock", "asn", "rirorg"},
		EventType:  oam.IPAddress,
		Handler:    bt.lookup,
	}); err != nil {
		r.Log.Printf("Failed to register the %s: %v", name, err)
		return err
	}
	return nil
}

func (bt *bgpTools) Stop() {}

// lookup function queries the bgptools whois server using an
// IP address to retrieve related ASN, netblock, and RIR details.
func (bt *bgpTools) lookup(e *et.Event) error {
	d, ok := e.Data.(*et.AssetData)
	if !ok {
		return errors.New("failed to extract the event data")
	}

	ip, ok := d.OAMAsset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	session := e.Session.(*sessions.Session)
	matches, err := checkTransformations(session, "ipaddress", "netblock", "asn", "rirorg", "bgptools")
	if err != nil || len(matches) == 0 {
		return err
	}

	ipstr := ip.Address.String()
	if reserved, _ := amassnet.IsReservedAddress(ipstr); reserved {
		return nil
	}

	if _, err := ipToNetblock(session, ip); err == nil {
		return nil
	}

	record, err := bt.query(ipstr)
	if err == nil {
		bt.process(e, ip, record, matches)
	}
	return err
}

func (bt *bgpTools) query(ipstr string) ([]string, error) {
	addr := net.JoinHostPort(bt.addr, strconv.Itoa(bt.port))
	conn, err := amassnet.DialContext(context.TODO(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to establish a connection with the WHOIS server: %v", err)
	}
	defer conn.Close()

	n, err := io.WriteString(conn, fmt.Sprintf("begin\n%s\nend", ipstr))
	if err != nil || n == 0 {
		return nil, fmt.Errorf("failed to send the request to the WHOIS server: %v", err)
	}

	data, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("error reading the response from the WHOIS server: %v", err)
	}

	record := strings.Split(string(data), "|")
	// Ensure the record contains the necessary details (ASN, netblock, RIR)
	if len(record) < 7 {
		return nil, errors.New("received insufficient data from the WHOIS server")
	}

	var results []string
	for _, v := range record {
		results = append(results, strings.TrimSpace(v))
	}
	return results, nil
}

func (bt *bgpTools) process(e *et.Event, ip *oamnet.IPAddress, record []string, matches map[string]struct{}) {
	now := time.Now()
	session := e.Session.(*sessions.Session)

	var as *dbt.Asset
	if asnstr := record[0]; asnstr != "" {
		if asn, err := strconv.Atoi(asnstr); err == nil {
			oamas := &oamnet.AutonomousSystem{Number: asn}

			if _, found := matches["asn"]; found {
				as, err = session.DB.Create(nil, "", oamas)
				if err == nil {
					scheduleAssetEvent(e, asnstr, as)
				}
			} else {
				as = &dbt.Asset{
					CreatedAt: now,
					LastSeen:  now,
					Asset:     oamas,
				}
				session.Cache.SetAsset(as)
			}
		}
	}

	if desc := record[6]; desc != "" {
		var rel string
		if as != nil {
			rel = "managed_by"
		}

		oamrir := &oamnet.RIROrganization{
			Name: desc,
			RIR:  record[4],
		}

		var rir *dbt.Asset
		if _, found := matches["rirorg"]; found {
			var err error

			rir, err = session.DB.Create(as, rel, oamrir)
			if err == nil {
				scheduleAssetEvent(e, desc, rir)
				if as != nil {
					session.Cache.SetRelation(&dbt.Relation{
						Type:      rel,
						CreatedAt: now,
						LastSeen:  now,
						FromAsset: as,
						ToAsset:   rir,
					})
				}
			}
		} else {
			rir = &dbt.Asset{
				CreatedAt: now,
				LastSeen:  now,
				Asset:     oamrir,
			}
			session.Cache.SetAsset(rir)
		}
	}

	if cidr := record[2]; cidr != "" {
		if prefix, err := netip.ParsePrefix(cidr); err == nil {
			oamnb := &oamnet.Netblock{
				Cidr: prefix,
				Type: "IPv6",
			}
			if prefix.Addr().Is4() {
				oamnb.Type = "IPv4"
			}

			var rel string
			if as != nil {
				rel = "announces"
			}

			var nb *dbt.Asset
			if _, found := matches["netblock"]; found {
				var err error

				nb, err = session.DB.Create(as, rel, oamnb)
				if err == nil {
					scheduleAssetEvent(e, cidr, nb)
					if as != nil {
						session.Cache.SetRelation(&dbt.Relation{
							Type:      rel,
							CreatedAt: now,
							LastSeen:  now,
							FromAsset: as,
							ToAsset:   nb,
						})
					}

					if a, err := session.DB.Create(nb, "contains", ip); err == nil {
						session.Cache.SetRelation(&dbt.Relation{
							Type:      "contains",
							CreatedAt: now,
							LastSeen:  now,
							FromAsset: nb,
							ToAsset:   a,
						})
					}
				}
			} else {
				nb = &dbt.Asset{
					CreatedAt: now,
					LastSeen:  now,
					Asset:     oamnb,
				}
				session.Cache.SetAsset(nb)
			}
		}
	}
}
