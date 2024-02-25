// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/caffix/queue"
	"github.com/miekg/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/graph"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/resolve"
	"golang.org/x/net/publicsuffix"
)

type subsQtypes struct {
	Qtype uint16
	Rtype string
}

type dnsSubs struct {
	types []subsQtypes
	queue queue.Queue
	done  chan struct{}
}

func NewSubs() et.Plugin {
	return &dnsSubs{
		types: []subsQtypes{
			{Qtype: dns.TypeNS, Rtype: "ns_record"},
			{Qtype: dns.TypeMX, Rtype: "mx_record"},
			//{Qtype: dns.TypeSOA, Rtype: "soa_record"},
			//{Qtype: dns.TypeSPF, Rtype: "spf_record"},
		},
		queue: queue.NewQueue(),
		done:  make(chan struct{}),
	}
}

func (d *dnsSubs) Start(r et.Registry) error {
	name := "DNS-Subdomains-Handler"

	if err := r.RegisterHandler(&et.Handler{
		Name:         name,
		Priority:     3,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{"fqdn"},
		EventType:    oam.FQDN,
		Callback:     d.check,
	}); err != nil {
		r.Log().Error(fmt.Sprintf("Failed to register a handler: %v", err), "handler", name)
		return err
	}

	go d.process()
	return nil
}

func (d *dnsSubs) Stop() {
	select {
	case <-d.done:
		return
	default:
	}
	close(d.done)
}

func (d *dnsSubs) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	matches, err := e.Session.Config().CheckTransformations("fqdn", "fqdn", "dns")
	if err != nil {
		return err
	}

	if matches.IsMatch("fqdn") && support.NameResolved(e.Session, fqdn) {
		d.traverse(e, fqdn)
	}
	return nil
}

func (d *dnsSubs) traverse(e *et.Event, n *domain.FQDN) {
	sub := n.Name
	var wg sync.WaitGroup

	dom := d.registered(e, sub)
	if dom == "" {
		return
	}
	if sub == dom {
		d.queries(e, sub, &wg)
		wg.Wait()
		return
	}
	dlabels := strings.Split(dom, ".")

	for {
		labels := strings.Split(sub, ".")
		// Is this large enough to consider further?
		if len(labels) < 2 {
			break
		}
		sub = strings.TrimSpace(strings.Join(labels[1:], "."))
		// no need to check subdomains already evaluated
		if _, hit := e.Session.Cache().GetAsset(&domain.FQDN{Name: sub}); hit {
			break
		}
		if len(dlabels) > len(labels) {
			break
		}
		d.queries(e, sub, &wg)
	}
	wg.Wait()
}

func (d *dnsSubs) queries(e *et.Event, subdomain string, wg *sync.WaitGroup) {
	apex := true

	for i, t := range d.types {
		if rr, err := support.PerformQuery(subdomain, t.Qtype); err == nil && len(rr) > 0 {
			wg.Add(1)
			d.callbackClosure(e, t.Rtype, rr, wg)
		} else if i == 0 {
			// do not continue if we failed to obtain the NS record
			apex = false
			break
		}
	}

	if !apex {
		return
	}

	for _, name := range srvNames {
		if rr, err := support.PerformQuery(name+"."+subdomain, dns.TypeSRV); err == nil && len(rr) > 0 {
			wg.Add(1)
			d.callbackClosure(e, "srv_record", rr, wg)
		}
	}
}

func (d *dnsSubs) callbackClosure(e *et.Event, rtype string, rr []*resolve.ExtractedAnswer, wg *sync.WaitGroup) {
	g := graph.Graph{DB: e.Session.DB()}

	d.queue.Append(func() {
		defer wg.Done()

		for _, record := range rr {
			fqdn, err := g.UpsertFQDN(context.TODO(), record.Name)
			if err != nil || fqdn == nil {
				continue
			}

			a, err := e.Session.DB().Create(fqdn, rtype, &domain.FQDN{Name: record.Data})
			if err != nil || a == nil {
				continue
			}

			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    record.Name,
				Asset:   fqdn,
				Session: e.Session,
			})

			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    record.Data,
				Asset:   a,
				Session: e.Session,
			})

			if from, hit := e.Session.Cache().GetAsset(fqdn.Asset); hit && from != nil {
				if to, hit := e.Session.Cache().GetAsset(a.Asset); hit && to != nil {
					now := time.Now()

					e.Session.Cache().SetRelation(&dbt.Relation{
						Type:      rtype,
						CreatedAt: now,
						LastSeen:  now,
						FromAsset: fqdn,
						ToAsset:   to,
					})
				}
			}
		}
	})
}

func (d *dnsSubs) process() {
	for {
		select {
		case <-d.done:
			return
		case <-d.queue.Signal():
			d.queue.Process(func(data interface{}) {
				if callback, ok := data.(func()); ok {
					callback()
				}
			})
		}
	}
}

func (d *dnsSubs) registered(e *et.Event, name string) string {
	if dom := e.Session.Config().WhichDomain(name); dom != "" {
		return dom
	}

	fqdn, hit := e.Session.Cache().GetAsset(&domain.FQDN{Name: name})
	if !hit || fqdn == nil {
		return ""
	}

	now := time.Now()
	var rels []*dbt.Relation
	for _, rtype := range []string{"ns_record", "mx_record"} {
		if r, hit := e.Session.Cache().GetRelations(&dbt.Relation{
			Type:      rtype,
			CreatedAt: now,
			LastSeen:  now,
			ToAsset:   fqdn,
		}); hit && len(r) > 0 {
			rels = append(rels, r...)
		}
	}

	var found bool
	for _, r := range rels {
		if from, ok := r.FromAsset.Asset.(*domain.FQDN); ok &&
			from != nil && e.Session.Config().IsDomainInScope(from.Name) {
			found = true
			break
		}
	}
	if found {
		if dom, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
			return dom
		}
	}
	return ""
}

var srvNames = []string{
	"_afs3-kaserver._tcp",
	"_afs3-kaserver._tcp",
	"_afs3-kaserver._udp",
	"_afs3-prserver._tcp",
	"_afs3-prserver._udp",
	"_afs3-vlserver._tcp",
	"_afs3-vlserver._udp",
	"_amt._udp",
	"_autodiscover._tcp",
	"_autotunnel._udp",
	"_avatars-sec._tcp",
	"_avatars._tcp",
	"_bittorrent-tracker._tcp",
	"_caldav._tcp",
	"_caldavs._tcp",
	"_carddav._tcp",
	"_carddavs._tcp",
	"_ceph-mon._tcp",
	"_ceph._tcp",
	"_certificates._tcp",
	"_chat._udp",
	"_citrixreceiver._tcp",
	"_collab-edge._tls",
	"_crls._tcp",
	"_daap._tcp",
	"_diameters._tcp",
	"_diameter._tcp",
	"_diameter._tls",
	"_dns-llq._tcp",
	"_dns-llq-tls._tcp",
	"_dns-llq-tls._udp",
	"_dns-llq._udp",
	"_dns-push-tls._tcp",
	"_dns-sd._udp",
	"_dns._udp",
	"_dns-update._tcp",
	"_dns-update-tls._tcp",
	"_dns-update._udp",
	"_dots-call-home._tcp",
	"_dots-call-home._udp",
	"_dots-data._tcp",
	"_dots-signal._tcp",
	"_dots-signal._udp",
	"_dvbservdsc._tcp",
	"_dvbservdsc._udp",
	"_ftp._tcp",
	"_gc._tcp",
	"_hip-nat-t._udp",
	"_http._tcp",
	"_hybrid-pop._tcp",
	"_hybrid-pop._udp",
	"_imap3._tcp",
	"_imap3._udp",
	"_imaps._tcp",
	"_imaps._udp",
	"_imap._tcp",
	"_imap._udp",
	"_imps-server._tcp",
	"_ipp._tcp",
	"_jabber._tcp",
	"_jmap._tcp",
	"_kca._udp",
	"_kerberos-adm._tcp",
	"_kerberos-adm._udp",
	"_kerberos-master._tcp",
	"_kerberos-master._udp",
	"_kerberos._tcp",
	"_kerberos-tls._tcp",
	"_kerberos._udp",
	"_kerneros-iv._udp",
	"_kftp-data._tcp",
	"_kftp-data._udp",
	"_kftp._tcp",
	"_kftp._udp",
	"_kpasswd._tcp",
	"_kpasswd._udp",
	"_ktelnet._tcp",
	"_ktelnet._udp",
	"_ldap-admin._tcp",
	"_ldap-admin._udp",
	"_ldaps._tcp",
	"_ldaps._udp",
	"_ldap._tcp",
	"_ldap._udp",
	"_matrix._tcp",
	"_matrix-vnet._tcp",
	"_MIHIS._tcp",
	"_MIHIS._udp",
	"_minecraft._tcp",
	"_msft-gc-ssl._tcp",
	"_msft-gc-ssl._udp",
	"_msrps._tcp",
	"_mtqp._tcp",
	"_nfs-domainroot._tcp",
	"_nicname._tcp",
	"_nicname._udp",
	"_ntp._udp",
	"_pop2._tcp",
	"_pop2._udp",
	"_pop3s._tcp",
	"_pop3s._udp",
	"_pop3._tcp",
	"_pop3._udp",
	"_presence._tcp",
	"_presence._udp",
	"_puppet._tcp",
	"_radiusdtls._udp",
	"_radiustls._tcp",
	"_radiustls._udp",
	"_radsec._tcp",
	"_rwhois._tcp",
	"_rwhois._udp",
	"_sieve._tcp",
	"_sips._tcp",
	"_sips._udp",
	"_sip._tcp",
	"_sip._udp",
	"_slpda._tcp",
	"_slpda._udp",
	"_slp._tcp",
	"_slp._udp",
	"_smtp._tcp",
	"_smtp._tls",
	"_smtp._udp",
	"_soap-beep._tcp",
	"_ssh._tcp",
	"_stun-behaviors._tcp",
	"_stun-behaviors._udp",
	"_stun-behavior._tcp",
	"_stun-behavior._udp",
	"_stun-p1._tcp",
	"_stun-p1._udp",
	"_stun-p2._tcp",
	"_stun-p2._udp",
	"_stun-p3._tcp",
	"_stun-p3._udp",
	"_stun-port._tcp",
	"_stun-port._udp",
	"_stuns._tcp",
	"_stuns._udp",
	"_stun._tcp",
	"_stun._udp",
	"_submissions._tcp",
	"_submission._tcp",
	"_submission._udp",
	"_sztp._tcp",
	"_telnet._tcp",
	"_timezones._tcp",
	"_timezone._tcp",
	"_ts3._udp",
	"_tsdns._tcp",
	"_tunnel._tcp",
	"_turns._tcp",
	"_turns._udp",
	"_turn._tcp",
	"_turn._udp",
	"_whoispp._tcp",
	"_whoispp._udp",
	"_www-http._tcp",
	"_www-ldap-gw._tcp",
	"_www-ldap-gw._udp",
	"_www._tcp",
	"_xmlrpc-beep._tcp",
	"_xmpp-bosh._tcp",
	"_xmpp-client._tcp",
	"_xmpp-client._udp",
	"_xmpp-server._tcp",
	"_xmpp-server._udp",
	"_xmpp._tcp",
	"_x-puppet._tcp",
}
