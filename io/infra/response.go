package infra

import (
	"log"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/owasp-amass/engine/io"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
)

// DNSResponse encapsulates data parsed from a DNS Answer.
// likely want the request with this.
type DNSResponse struct {
	Name string
	Type uint16
	Data string
}

func (r DNSResponse) RequestFuncs() [](func() io.Request) {
	// send all FQDNs from the DNSResponse to generate a function that returns a DNSRequest
	return nil
}

func (r DNSResponse) AssetRelation() (string, oam.Asset) {
	// likely don't need to pass r through to another function...
	return assetForType(r.Data, r.Type)
}

func (r DNSResponse) Source() string {
	return "DNSResolver"
}

func assetForType(data string, t uint16) (string, oam.Asset) {
	switch t {
	case dns.TypeA: // A
		ip, err := netip.ParseAddr(data)
		if err != nil {
			return "", nil
		}
		return "a_record", network.IPAddress{
			Address: ip,
			Type:    "IPv4",
		}
	case dns.TypeNS:
		return "ns_record", domain.FQDN{
			Name: data,
		}
	case dns.TypeCNAME:
		return "cname_record", domain.FQDN{
			Name: data,
		}
	case dns.TypeSOA:
		return "soa_record", domain.FQDN{
			Name: data,
		}
	case dns.TypePTR:
		return "ptr_record", domain.FQDN{
			Name: data,
		}
	case dns.TypeMX:
		return "mx_record", domain.FQDN{
			Name: data,
		}

	case dns.TypeTXT:

	case dns.TypeAAAA:
		ipv6, err := netip.ParseAddr(data)
		if err != nil {
			log.Println("[ERROR] Could not parse IPv6 address:", data)
			return "", nil
		}
		return "aaaa_record", network.IPAddress{
			Address: ipv6,
			Type:    "IPv6",
		}
	default:
		log.Println("[ERROR] Unknown DNS response type:", t)
		return "", nil
	}
	return "", nil
}
