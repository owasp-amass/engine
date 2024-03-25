// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/config/config"
	amassnet "github.com/owasp-amass/engine/net"
	"github.com/owasp-amass/engine/net/http"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"go.uber.org/ratelimit"
)

type row struct {
	Netblock string `json:"CIDR"`
	ASN      int    `json:"ASN"`
}

type bgpTools struct {
	name   string
	m      sync.Mutex
	addr   string
	port   int
	log    *slog.Logger
	rlimit ratelimit.Limiter
}

func NewBGPTools() et.Plugin {
	return &bgpTools{
		name:   "BGPTools",
		port:   43,
		rlimit: ratelimit.New(1, ratelimit.WithoutSlack),
	}
}

func (bt *bgpTools) Name() string {
	return bt.name
}

func (bt *bgpTools) Start(r et.Registry) error {
	bt.log = r.Log().WithGroup("plugin").With("name", bt.name)

	rr, err := support.PerformQuery("bgp.tools", dns.TypeA)
	if err != nil {
		return fmt.Errorf("failed to obtain the BGPTools IP address: %v", err)
	}
	bt.addr = rr[0].Data

	name := bt.name + "-IP-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       bt,
		Name:         name,
		Priority:     1,
		MaxInstances: 50,
		Transforms:   []string{"netblock", "asn", "rirorg"},
		EventType:    oam.IPAddress,
		Callback:     bt.lookup,
	}); err != nil {
		return err
	}

	bt.log.Info("Plugin started")
	return nil
}

func (bt *bgpTools) Stop() {
	bt.log.Info("Plugin stopped")
}

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

	matches, err := e.Session.Config().CheckTransformations(
		"ipaddress", "netblock", "asn", "rirorg", bt.name)
	if err != nil || matches.Len() == 0 {
		return err
	}

	if _, err := support.IPToNetblock(e.Session, ip); err == nil {
		return nil
	}

	bt.m.Lock()
	dir := config.OutputDirectory("")
	if bt.needTableFile(dir) {
		if err := bt.getTableFile(dir); err != nil {
			bt.m.Unlock()
			return err
		}
	}
	if row := bt.netblock(dir, net.ParseIP(ipstr)); row != nil {
		if as, hit := e.Session.Cache().GetAsset(
			&oamnet.AutonomousSystem{Number: row.ASN}); hit && as != nil {
			bt.submitNetblock(e, row, as)
			bt.m.Unlock()
			return nil
		}
	}
	bt.m.Unlock()

	bt.rlimit.Take()
	record, err := bt.query(ipstr)
	if err == nil {
		bt.process(e, record, matches)
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

func (bt *bgpTools) process(e *et.Event, record []string, matches *config.Matches) {
	now := time.Now()
	var as *dbt.Asset
	var oamas *oamnet.AutonomousSystem
	group := slog.Group("plugin", "name", bt.name, "handler", bt.name+"-IP-Handler")

	if asnstr := record[0]; asnstr != "" {
		if asn, err := strconv.Atoi(asnstr); err == nil {
			oamas = &oamnet.AutonomousSystem{Number: asn}

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

					e.Session.Log().Info("relationship discovered",
						"from", oamas.Number, "relation", rel, "to", desc, group)
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

						e.Session.Log().Info("relationship discovered",
							"from", oamas.Number, "relation", rel, "to", cidr, group)
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

func (bt *bgpTools) netblock(dir string, ip net.IP) *row {
	f, err := os.Open(filepath.Join(dir, "bgptools.jsonl"))
	if err != nil || f == nil {
		return nil
	}
	defer f.Close()

	var cur row
	var cidr *net.IPNet
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var line row

		err := json.Unmarshal([]byte(scanner.Text()), &line)
		if err != nil {
			continue
		}

		_, ipnet, err := net.ParseCIDR(line.Netblock)
		if err != nil {
			continue
		}

		if ones, _ := ipnet.Mask.Size(); ones == 0 {
			continue
		}

		if ipnet.Contains(ip) {
			// Select the smallest CIDR
			if cidr != nil {
				s1, _ := cidr.Mask.Size()
				s2, _ := ipnet.Mask.Size()
				if s1 > s2 {
					continue
				}
			}
			cur = line
			cidr = ipnet
		}
	}
	return &cur
}

func (bt *bgpTools) submitNetblock(e *et.Event, line *row, as *dbt.Asset) {
	if prefix, err := netip.ParsePrefix(line.Netblock); err == nil {
		oamnb := &oamnet.Netblock{
			Cidr: prefix,
			Type: "IPv6",
		}
		if prefix.Addr().Is4() {
			oamnb.Type = "IPv4"
		}

		if nb, err := e.Session.DB().Create(as, "announces", oamnb); err == nil && nb != nil {
			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    line.Netblock,
				Asset:   nb,
				Session: e.Session,
			})

			now := time.Now()
			e.Session.Cache().SetRelation(&dbt.Relation{
				Type:      "announces",
				CreatedAt: now,
				LastSeen:  now,
				FromAsset: as,
				ToAsset:   nb,
			})
			if oamas, ok := as.Asset.(*oamnet.AutonomousSystem); ok {
				e.Session.Log().Info("relationship discovered", "from",
					oamas.Number, "relation", "announces", "to", line.Netblock,
					slog.Group("plugin", "name", bt.name, "handler", bt.name+"-IP-Handler"))
			}
		}
	}
}

func (bt *bgpTools) needTableFile(dir string) bool {
	f, err := os.Open(filepath.Join(dir, "bgptools.jsonl"))
	if err != nil || f == nil {
		return true
	}
	defer f.Close()

	if info, err := f.Stat(); err == nil && info != nil {
		if max := time.Now().Add(-24 * time.Hour); info.ModTime().Before(max) {
			return true
		}
	}
	return false
}

func (bt *bgpTools) getTableFile(dir string) error {
	header := make(http.Header)
	header["User-Agent"] = "OWASP Amass v4.2.0 - admin@owasp.com"

	resp, err := http.RequestWebPage(context.TODO(), &http.Request{
		URL:    "https://bgp.tools/table.jsonl",
		Header: header,
	})
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return errors.New("table.jsonl file request returned with status: " + resp.Status)
	}

	f, err := os.Create(filepath.Join(dir, "bgptools.jsonl"))
	if err != nil || f == nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(resp.Body)
	return err
}
