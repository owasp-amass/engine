// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/scheduler"
	"github.com/owasp-amass/engine/sessions"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/network"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/resolve"
)

func scheduleAssetEvent(e *et.Event, name string, a *dbt.Asset) {
	session := e.Session.(*sessions.Session)
	s := e.Sched.(*scheduler.Scheduler)

	if err := s.Schedule(&et.Event{
		UUID:      uuid.New(),
		SessionID: e.SessionID,
		Name:      name,
		Type:      et.EventTypeAsset,
		State:     et.EventStateDefault,
		Data: &et.AssetData{
			OAMAsset: a.Asset,
			OAMType:  a.Asset.AssetType(),
		},
	}); err == nil {
		session.Cache.SetAsset(a)
	}
}

func checkTransformations(session *sessions.Session, from string, tos ...string) (map[string]struct{}, error) {
	lower := strings.ToLower(from)
	tomap := make(map[string]struct{})
	results := make(map[string]struct{})

	for _, v := range tos {
		t := strings.ToLower(v)
		tomap[t] = struct{}{}
	}

	for _, transform := range session.Cfg.Transformations {
		if tf := strings.ToLower(transform.From); lower == tf {
			tto := strings.ToLower(transform.To)

			if tto == "all" {
				excludes := make(map[string]struct{})
				for _, e := range transform.Exclude {
					excludes[strings.ToLower(e)] = struct{}{}
				}

				for k := range tomap {
					if _, found := excludes[k]; !found {
						results[k] = struct{}{}
					}
				}
				continue
			} else if _, found := tomap[tto]; found {
				results[tto] = struct{}{}
			}
		}
	}

	if len(results) == 0 {
		return nil, errors.New("zero transformation matches in the session config")
	}
	return results, nil
}

func performQuery(name string, qtype uint16) ([]*resolve.ExtractedAnswer, error) {
	msg := resolve.QueryMsg(name, qtype)
	if qtype == dns.TypePTR {
		msg = resolve.ReverseMsg(name)
	}

	resp, err := dnsQuery(msg, 10)
	if err == nil {
		if ans := resolve.ExtractAnswers(resp); len(ans) > 0 {
			if rr := resolve.AnswersByType(ans, qtype); len(rr) > 0 {
				return rr, nil
			}
		}
	}
	return nil, err
}

func dnsQuery(msg *dns.Msg, attempts int) (*dns.Msg, error) {
	for num := 0; num < attempts; num++ {
		resp, err := dns.Exchange(msg, "8.8.8.8:53")
		if err != nil {
			continue
		}
		if resp.Rcode == dns.RcodeNameError {
			return nil, errors.New("name does not exist")
		}
		if resp.Rcode == dns.RcodeSuccess {
			if len(resp.Answer) == 0 {
				return nil, errors.New("no record of this type")
			}
			return resp, nil

		}
	}
	return nil, errors.New("failed to receive a DNS response")
}

func ipToNetblockWithAttempts(session *sessions.Session, ip *network.IPAddress, num int, d time.Duration) (*network.Netblock, error) {
	var err error
	var nb *network.Netblock

	for i := 0; i < num; i++ {
		nb, err = ipToNetblock(session, ip)
		if err == nil {
			break
		}
		time.Sleep(d)
	}

	return nb, err
}

func ipToNetblock(session *sessions.Session, ip *network.IPAddress) (*network.Netblock, error) {
	if assets, hit := session.Cache.GetAssetsByType(oam.Netblock); hit && len(assets) > 0 {
		for _, a := range assets {
			if nb, ok := a.Asset.(*oamnet.Netblock); ok && nb.Cidr.Contains(ip.Address) {
				return nb, nil
			}
		}
	}
	return nil, errors.New("no netblock match in the cache")
}
