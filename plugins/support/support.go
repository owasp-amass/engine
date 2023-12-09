// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"errors"
	"time"

	"github.com/miekg/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/resolve"
)

func PerformQuery(name string, qtype uint16) ([]*resolve.ExtractedAnswer, error) {
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

func IPToNetblockWithAttempts(session et.Session, ip *oamnet.IPAddress, num int, d time.Duration) (*oamnet.Netblock, error) {
	var err error
	var nb *oamnet.Netblock

	for i := 0; i < num; i++ {
		nb, err = IPToNetblock(session, ip)
		if err == nil {
			break
		}
		time.Sleep(d)
	}

	return nb, err
}

func IPToNetblock(session et.Session, ip *oamnet.IPAddress) (*oamnet.Netblock, error) {
	if assets, hit := session.Cache().GetAssetsByType(oam.Netblock); hit && len(assets) > 0 {
		for _, a := range assets {
			if nb, ok := a.Asset.(*oamnet.Netblock); ok && nb.Cidr.Contains(ip.Address) {
				return nb, nil
			}
		}
	}
	return nil, errors.New("no netblock match in the cache")
}

func IsAddressInScope(session et.Session, ip *oamnet.IPAddress) bool {
	addr, hit := session.Cache().GetAsset(ip)
	if !hit || addr == nil {
		return false
	}

	rtype := "a_record"
	if ip.Type == "IPv6" {
		rtype = "aaaa_record"
	}

	if relations, hit := session.Cache().GetRelations(&dbt.Relation{
		Type:    rtype,
		ToAsset: addr,
	}); hit && len(relations) > 0 {
		for _, relation := range relations {
			a := relation.FromAsset.Asset

			if fqdn, ok := a.(*domain.FQDN); ok && session.Config().IsDomainInScope(fqdn.Name) {
				return true
			}
		}
	}

	return false
}
