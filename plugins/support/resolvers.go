// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/caffix/queue"
	"github.com/caffix/stringset"
	"github.com/miekg/dns"
	"github.com/owasp-amass/engine/graph"
	"github.com/owasp-amass/engine/net/http"
	et "github.com/owasp-amass/engine/types"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/resolve"
	"golang.org/x/net/publicsuffix"
)

// queriesPerPublicResolver is the number of queries sent to each public DNS resolver per second.
const queriesPerPublicResolver = 5

// queriesPerBaselineResolver is the number of queries sent to each trusted DNS resolver per second.
const queriesPerBaselineResolver = 15

const minResolverReliability = 0.85

type guess struct {
	event *et.Event
	name  string
}

// baselineResolvers is a list of trusted public DNS resolvers.
var baselineResolvers = []string{
	"8.8.8.8",        // Google
	"1.1.1.1",        // Cloudflare
	"9.9.9.9",        // Quad9
	"208.67.222.222", // Cisco OpenDNS
	"84.200.69.80",   // DNS.WATCH
	"64.6.64.6",      // Neustar DNS
	"8.26.56.26",     // Comodo Secure DNS
	"205.171.3.65",   // Level3
	"134.195.4.2",    // OpenNIC
	"185.228.168.9",  // CleanBrowsing
	"76.76.19.19",    // Alternate DNS
	"37.235.1.177",   // FreeDNS
	"77.88.8.1",      // Yandex.DNS
	"94.140.14.140",  // AdGuard
	"38.132.106.139", // CyberGhost
	"74.82.42.42",    // Hurricane Electric
	"76.76.2.0",      // ControlD
}

var trusted *resolve.Resolvers
var untrusted *resolve.Resolvers
var guesses queue.Queue

func init() {
	rate := resolve.NewRateTracker()

	trusted, _ = trustedResolvers()
	trusted.SetRateTracker(rate)
	untrusted, _ = untrustedResolvers()
	untrusted.SetRateTracker(rate)

	if untrusted != nil {
		guesses = queue.NewQueue()
		go processGuesses()
	}
}

func NumTrustedResolvers() int {
	return trusted.Len()
}

func NumUntrustedResolvers() int {
	return untrusted.Len()
}

func PerformQuery(name string, qtype uint16) ([]*resolve.ExtractedAnswer, error) {
	msg := resolve.QueryMsg(name, qtype)
	if qtype == dns.TypePTR {
		msg = resolve.ReverseMsg(name)
	}

	resp, err := dnsQuery(msg, trusted, 50)
	if err == nil && resp != nil && !wildcardDetected(resp) {
		if ans := resolve.ExtractAnswers(resp); len(ans) > 0 {
			if rr := resolve.AnswersByType(ans, qtype); len(rr) > 0 {
				return normalize(rr), nil
			}
		}
	}
	return nil, err
}

func PerformUntrustedQuery(name string, qtype uint16) ([]*resolve.ExtractedAnswer, error) {
	msg := resolve.QueryMsg(name, qtype)
	if qtype == dns.TypePTR {
		msg = resolve.ReverseMsg(name)
	}

	resp, err := dnsQuery(msg, untrusted, 50)
	if err == nil && resp != nil {
		if ans := resolve.ExtractAnswers(resp); len(ans) > 0 {
			if rr := resolve.AnswersByType(ans, qtype); len(rr) > 0 {
				return normalize(rr), nil
			}
		}
	}
	return nil, err
}

func SubmitFQDNGuess(e *et.Event, name string) {
	if untrusted != nil {
		guesses.Append(&guess{
			event: e,
			name:  name,
		})
	}
}

func processGuesses() {
	if untrusted == nil {
		return
	}

	num := untrusted.Len()
	ch := make(chan struct{}, num)
	for i := 0; i < num; i++ {
		ch <- struct{}{}
	}

	for {
		select {
		case <-done:
			return
		case <-guesses.Signal():
			guesses.Process(func(data interface{}) {
				<-ch
				if g, ok := data.(*guess); ok && g != nil {
					go guessAttempt(g.event, g.name, ch)
				}
			})
		}
	}
}

func guessAttempt(e *et.Event, name string, ch chan struct{}) {
	defer func() { ch <- struct{}{} }()

	if _, hit := e.Session.Cache().GetAsset(&domain.FQDN{Name: name}); hit {
		return
	}

	for _, qtype := range []uint16{dns.TypeCNAME, dns.TypeA, dns.TypeAAAA} {
		msg := resolve.QueryMsg(name, qtype)

		if resp, err := dnsQuery(msg, untrusted, 50); err == nil && resp != nil {
			guessCallback(e, name)
		}
	}
}

func guessCallback(e *et.Event, name string) {
	g := graph.Graph{DB: e.Session.DB()}

	AppendToDBQueue(func() {
		fqdn, err := g.UpsertFQDN(context.TODO(), name)
		if err != nil {
			e.Session.Log().Println(err.Error())
			return
		}
		if fqdn != nil {
			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    name,
				Asset:   fqdn,
				Session: e.Session,
			})
		}
	})
}

func wildcardDetected(resp *dns.Msg) bool {
	name := strings.ToLower(resolve.RemoveLastDot(resp.Question[0].Name))

	if dom, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil && dom != "" {
		return trusted.WildcardDetected(context.TODO(), resp, dom)
	}
	return false
}

func normalize(records []*resolve.ExtractedAnswer) []*resolve.ExtractedAnswer {
	var results []*resolve.ExtractedAnswer

	for _, rr := range records {
		results = append(results, &resolve.ExtractedAnswer{
			Name: strings.ToLower(rr.Name),
			Type: rr.Type,
			Data: strings.ToLower(rr.Data),
		})
	}

	return results
}

func dnsQuery(msg *dns.Msg, r *resolve.Resolvers, attempts int) (*dns.Msg, error) {
	for num := 0; num < attempts; num++ {
		resp, err := r.QueryBlocking(context.TODO(), msg)
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
	return nil, nil
}

func trustedResolvers() (*resolve.Resolvers, int) {
	if pool := resolve.NewResolvers(); pool != nil {
		_ = pool.AddResolvers(queriesPerBaselineResolver, baselineResolvers...)
		pool.SetDetectionResolver(queriesPerBaselineResolver, "8.8.8.8")
		pool.SetTimeout(2 * time.Second)
		return pool, pool.Len()
	}
	return nil, 0
}

func untrustedResolvers() (*resolve.Resolvers, int) {
	resolvers, err := publicDNSResolvers()
	if err != nil {
		return nil, 0
	}

	resolvers = checkAddresses(stringset.Deduplicate(resolvers))
	if len(resolvers) == 0 {
		return nil, 0
	}

	if pool := resolve.NewResolvers(); pool != nil {
		_ = pool.AddResolvers(queriesPerPublicResolver, resolvers...)
		pool.SetTimeout(3 * time.Second)
		pool.SetThresholdOptions(&resolve.ThresholdOptions{
			ThresholdValue:      20,
			CountTimeouts:       true,
			CountFormatErrors:   true,
			CountServerFailures: true,
			CountNotImplemented: true,
			CountQueryRefusals:  true,
		})
		pool.ClientSubnetCheck()
		return pool, pool.Len()
	}
	return nil, 0
}

func checkAddresses(addrs []string) []string {
	ips := []string{}

	for _, addr := range addrs {
		ip, port, err := net.SplitHostPort(addr)
		if err != nil {
			ip = addr
			port = "53"
		}
		if net.ParseIP(ip) == nil {
			continue
		}
		ips = append(ips, net.JoinHostPort(ip, port))
	}
	return ips
}

// publicDNSResolvers obtains the public DNS server addresses from public-dns.info.
func publicDNSResolvers() ([]string, error) {
	url := "https://public-dns.info/nameservers-all.csv"
	resp, err := http.RequestWebPage(context.Background(), &http.Request{URL: url})
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, fmt.Errorf("failed to obtain the Public DNS csv file at %s: %v", url, err)
	}

	var resolvers []string
	var ipIdx, reliabilityIdx int
	r := csv.NewReader(strings.NewReader(resp.Body))
	for i := 0; ; i++ {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if i == 0 {
			for idx, val := range record {
				if val == "ip_address" {
					ipIdx = idx
				} else if val == "reliability" {
					reliabilityIdx = idx
				}
			}
			continue
		}
		if rel, err := strconv.ParseFloat(record[reliabilityIdx], 64); err == nil && rel >= minResolverReliability {
			resolvers = append(resolvers, record[ipIdx])
		}
	}

	var results []string
loop:
	for _, addr := range resolvers {
		for _, br := range baselineResolvers {
			if addr == br {
				continue loop
			}
		}
		results = append(results, strings.TrimSpace(addr))
	}
	return results, nil
}
