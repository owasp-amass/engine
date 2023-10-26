// This is a very simple GraphQL client for testing
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/owasp-amass/config/config"
	oam "github.com/owasp-amass/open-asset-model"
	fqdn "github.com/owasp-amass/open-asset-model/domain"
	oamNet "github.com/owasp-amass/open-asset-model/network"
)

type Client struct {
	url        string
	httpClient http.Client
}

type DoesAutoBindFindeMe struct {
	answer string
}

func NewClient(url string) *Client {

	httpClient := &http.Client{}
	return &Client{url: url, httpClient: *httpClient}
}

func (c *Client) Query(query string) (string, error) {

	escapedQuery, err := json.Marshal(query)

	//body, err := json.Marshal(fmt.Sprintf(`{"query":"%s"}`, query))
	body := []byte(fmt.Sprintf(`{"query":%s}`, escapedQuery))
	//body := []byte(fmt.Sprintf(`{"query":"%s"}`, query))

	fmt.Println("BODY:\n" + string(body))
	req, err := http.NewRequest(http.MethodPost, c.url, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}

	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)

	if res.StatusCode != http.StatusOK {
		fmt.Println(string(resBody))
		return "error", err
	}

	return string(resBody), nil
}

func (c *Client) createSession(config *config.Config) (uuid.UUID, error) {

	var data interface{}
	configJson, err := json.Marshal(config)
	err = json.Unmarshal(configJson, &data)

	q := gqlEncoder(data)
	q = strings.ReplaceAll(q, "->", "_to_")

	queryStr := fmt.Sprintf(`mutation { createSession(input: {config: %s}) {token} }`, string(q))
	res, err := c.Query(queryStr)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Response:" + res)

	type createSession struct {
		token string
	}
	type gqlResponse struct {
		data createSession
	}

	var gqlResp struct {
		Data struct{ CreateSession struct{ Token string } }
	}
	err = json.Unmarshal([]byte(res), &gqlResp)

	token, _ := uuid.Parse(gqlResp.Data.CreateSession.Token)

	return token, nil
}

func (c *Client) createSessionWithJSON(config *config.Config) (uuid.UUID, error) {

	var token uuid.UUID
	configJson, err := json.Marshal(config)
	if err != nil {
		fmt.Println(err)
		return token, err
	}

	fmt.Println(string(configJson))
	quotedStr := strconv.Quote((string(configJson)))
	fmt.Println(string(quotedStr))
	queryStr := fmt.Sprintf(`mutation { createSessionFromJson(input: {config: %s}) {token} }`, quotedStr)

	res, err := c.Query(queryStr)

	fmt.Println("Response:" + res)

	var gqlResp struct {
		Data struct{ CreateSessionFromJson struct{ Token string } }
	}
	err = json.Unmarshal([]byte(res), &gqlResp)
	if err != nil {
		fmt.Println(err)
		return token, err
	}

	token, _ = uuid.Parse(gqlResp.Data.CreateSessionFromJson.Token)

	return token, nil
}

func (c *Client) createEvent(asset Asset, token uuid.UUID) {

	asset.Session = token

	assetJson, err := json.Marshal(asset)
	if err != nil {
		fmt.Println(err)
	}

	var data interface{}
	err = json.Unmarshal(assetJson, &data)
	q := gqlEncoder(data)

	queryStr := fmt.Sprintf(`mutation { createEvent(input:  %s) {id} }`, string(q))

	res, err := c.Query(queryStr)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Response:" + res)
}

// returns Asset objects by converting the contests of config.Scope
func makeAssets(config *config.Config) []*Asset {

	assets := convertScopeToAssets(config.Scope)
	for i, asset := range assets {
		asset.Event = fmt.Sprintf("asset#%d", i+1)
	}

	return assets
}

// Converts unmarshalled JSON into graphql field syntax
// This is a simple function for testing
func gqlEncoder(data interface{}) string {
	var q string

	switch data.(type) {
	case map[string]interface{}:
		q += "{\n"
		for key, val := range data.(map[string]interface{}) {
			q += fmt.Sprintf("%s: %v\n", key, gqlEncoder(val))
		}
		//q = strings.TrimRight(q, ", ")
		q += "}\n"
	case []interface{}:
		q += "["
		for _, val := range data.([]interface{}) {
			q += fmt.Sprintf("%v, ", gqlEncoder(val))
		}
		q = strings.TrimRight(q, ", ")
		q += "]"
	case string:
		q += fmt.Sprintf("\"%s\"", data)
	default:
		q += fmt.Sprintf("%v", data)
	}

	return q
}

const (
	ipv4 = "IPv4"
	ipv6 = "IPv6"
)

type Asset struct {
	Session uuid.UUID `json:"session_id,omitempty"`
	Event   string    `json:"event_name,omitempty"`
	Data    AssetData `json:"data,omitempty"`
}

type AssetData struct {
	OAMAsset oam.Asset     `json:"asset"`
	OAMType  oam.AssetType `json:"type"`
}

// ipnet2Prefix converts a net.IPNet to a netip.Prefix.
func ipnet2Prefix(ipn net.IPNet) netip.Prefix {
	addr, _ := netip.AddrFromSlice(ipn.IP)
	cidr, _ := ipn.Mask.Size()
	return netip.PrefixFrom(addr, cidr)
}

// convertScopeToAssets converts all items in a Scope to a slice of *Asset.
func convertScopeToAssets(scope *config.Scope) []*Asset {
	var assets []*Asset

	// Convert Domains to assets.
	for _, domain := range scope.Domains {
		fqdn := fqdn.FQDN{Name: domain}
		data := AssetData{
			OAMAsset: fqdn,
			OAMType:  fqdn.AssetType(),
		}
		asset := &Asset{
			Data: data,
		}
		assets = append(assets, asset)
	}

	var ipType string

	// Convert Addresses to assets.
	for _, ip := range scope.Addresses {
		// Convert net.IP to net.IPAddr.
		if addr, ok := netip.AddrFromSlice(ip); ok {
			// Determine the IP type based on the address characteristics.
			if addr.Is4In6() {
				addr = netip.AddrFrom4(addr.As4())
				ipType = ipv4
			} else if addr.Is6() {
				ipType = ipv6
			} else {
				ipType = ipv4
			}

			// Create an asset from the IP address and append it to the assets slice.
			asset := oamNet.IPAddress{Address: addr, Type: ipType}
			data := AssetData{
				OAMAsset: asset,
				OAMType:  asset.AssetType(),
			}
			assets = append(assets, &Asset{Data: data})
		}
	}

	// Convert CIDRs to assets.
	for _, cidr := range scope.CIDRs {
		prefix := ipnet2Prefix(*cidr) // Convert net.IPNet to netip.Prefix.

		// Determine the IP type based on the address characteristics.
		addr := prefix.Addr()
		if addr.Is4In6() {
			ipType = ipv4
		} else if addr.Is6() {
			ipType = ipv6
		} else {
			ipType = ipv4
		}

		// Create an asset from the CIDR and append it to the assets slice.
		asset := oamNet.Netblock{Cidr: prefix, Type: ipType}
		data := AssetData{
			OAMAsset: asset,
			OAMType:  asset.AssetType(),
		}
		assets = append(assets, &Asset{Data: data})
	}

	// Convert ASNs to assets.
	for _, asn := range scope.ASNs {
		asset := oamNet.AutonomousSystem{Number: asn}
		data := AssetData{
			OAMAsset: asset,
			OAMType:  asset.AssetType(),
		}
		assets = append(assets, &Asset{Data: data})
	}

	return assets
}
