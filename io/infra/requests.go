package infra

import (
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
)

// Given a source asset, generate an initial set of DNSRequests.
func RequestsForDomain(fqdn domain.FQDN) []DNSRequest {
	requests := []DNSRequest{}
	for _, qt := range []int{1, 2, 5, 6, 12, 15, 28} {
		requests = append(requests, DNSRequest{
			FQDN:  fqdn.Name,
			QType: qt,
		})
	}

	return requests
}

type DNSRequest struct {
	FQDN  string
	QType int
}

func (r DNSRequest) Type() string {
	return "DNS_REQUEST"
}

func (r DNSRequest) SourceAsset() oam.Asset {
	return domain.FQDN{
		Name: r.FQDN,
	}
}

type ReverseDNSRequest struct {
	Address string
}

func (r *ReverseDNSRequest) Type() string {
	return "REVERSE_DNS_REQUEST"
}
