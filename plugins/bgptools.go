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
	"github.com/owasp-amass/config/config"
	amassnet "github.com/owasp-amass/engine/net"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

type bgpTools struct {
	addr string
	port int
}

func newBGPTools() et.Plugin {
	return &bgpTools{port: 43}
}

func (bt *bgpTools) Start(r et.Registry) error {
	rr, err := support.PerformQuery("bgp.tools", dns.TypeA)
	if err != nil {
		return fmt.Errorf("failed to obtain the BGPTools IP address: %v", err)
	}
	bt.addr = rr[0].Data

	name := "BGPTools-IP-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Name:       name,
		Priority:   1,
		Transforms: []string{"netblock", "asn", "rirorg"},
		EventType:  oam.IPAddress,
		Callback:   bt.lookup,
	}); err != nil {
		r.Log().Printf("Failed to register the %s: %v", name, err)
		return err
	}
	return nil
}

func (bt *bgpTools) Stop() {}

// lookup function queries the bgptools whois server using an
// IP address to retrieve related ASN, netblock, and RIR details.
func (bt *bgpTools) lookup(e *et.Event) error {
	ip, ok := e.Asset.Asset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	ipstr := ip.Address.String()
	if reserved, _ := amassnet.IsReservedAddress(ipstr); reserved {
		return nil
	}

	matches, err := e.Session.Config().CheckTransformations("ipaddress", "netblock", "asn", "rirorg", "bgptools")
	if err != nil || matches.Len() == 0 {
		return err
	}

	if _, err := support.IPToNetblock(e.Session, ip); err == nil {
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

func (bt *bgpTools) process(e *et.Event, ip *oamnet.IPAddress, record []string, matches *config.Matches) {
	now := time.Now()
	var as *dbt.Asset

	if asnstr := record[0]; asnstr != "" {
		if asn, err := strconv.Atoi(asnstr); err == nil {
			oamas := &oamnet.AutonomousSystem{Number: asn}

			if matches.IsMatch("asn") {
				as, err = e.Session.DB().Create(nil, "", oamas)
				if err == nil {
					_ = e.Dispatcher.DispatchEvent(&et.Event{
						Name:    asnstr,
						Asset:   as,
						Session: e.Session,
					})
				}
			} else {
				as = &dbt.Asset{
					CreatedAt: now,
					LastSeen:  now,
					Asset:     oamas,
				}
				e.Session.Cache().SetAsset(as)
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
		if matches.IsMatch("rirorg") {
			var err error

			rir, err = e.Session.DB().Create(as, rel, oamrir)
			if err == nil {
				_ = e.Dispatcher.DispatchEvent(&et.Event{
					Name:    desc,
					Asset:   rir,
					Session: e.Session,
				})
				if as != nil {
					e.Session.Cache().SetRelation(&dbt.Relation{
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
			e.Session.Cache().SetAsset(rir)
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
			if matches.IsMatch("netblock") {
				var err error

				nb, err = e.Session.DB().Create(as, rel, oamnb)
				if err == nil {
					_ = e.Dispatcher.DispatchEvent(&et.Event{
						Name:    cidr,
						Asset:   nb,
						Session: e.Session,
					})
					if as != nil {
						e.Session.Cache().SetRelation(&dbt.Relation{
							Type:      rel,
							CreatedAt: now,
							LastSeen:  now,
							FromAsset: as,
							ToAsset:   nb,
						})
					}

					if a, err := e.Session.DB().Create(nb, "contains", ip); err == nil {
						e.Session.Cache().SetRelation(&dbt.Relation{
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
				e.Session.Cache().SetAsset(nb)
			}
		}
	}
}
