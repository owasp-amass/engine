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
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/engine/types"
	fqdn "github.com/owasp-amass/open-asset-model/domain"
	oamNet "github.com/owasp-amass/open-asset-model/network"
)

type Handler func(message string)

type Client struct {
	url        string
	httpClient http.Client
}

func NewClient(url string) *Client {

	httpClient := &http.Client{}
	return &Client{url: url, httpClient: *httpClient}
}

func (c *Client) Subscribe(token uuid.UUID, handler Handler) {

	parsedURL, _ := url.Parse(c.url)
	parsedURL.Scheme = "ws"

	conn, _, err := websocket.DefaultDialer.Dial(parsedURL.String(), nil)
	if err != nil {
		fmt.Println("Error connecting to the WebSocket server:", err)
	}
	defer conn.Close()

	// Request subscription from the graphql server
	query := fmt.Sprintf(`{"query": subscription { logger(sessionToken: "%s") {message} } }`, token.String())
	err = conn.WriteMessage(websocket.TextMessage, []byte(query))
	if err != nil {
		//if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		//}
		fmt.Println("Failed to send subscription query", err)
	}

	fmt.Println("out here:", err)
	go func() {
		fmt.Println("Inside here:", err)
		for {
			messageType, p, err := conn.ReadMessage()
			fmt.Println("and here:", err)
			if err != nil {
				fmt.Println("Error reading message:", err)
				//close(done)
				return
			}

			if messageType == websocket.TextMessage {
				fmt.Printf("Received message: %s\n", p)
			} else {
				fmt.Printf("Received message: %s\n", p)
			}
		}
	}()
}

func (c *Client) Query(query string) (string, error) {

	//escapedQuery, err := json.Marshal(query)

	quotedStr := strings.Trim(strconv.Quote((string(query))), `"`)

	//body, err := json.Marshal(fmt.Sprintf(`{"query":"%s"}`, query))
	body := []byte(fmt.Sprintf(`{"query":"%s"}`, quotedStr))
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
	//q = strings.ReplaceAll(q, "->", "_to_")

	queryStr := fmt.Sprintf(`mutation { createSession(input: {config: %s}) {sessionToken} }`, string(q))
	res, err := c.Query(queryStr)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Response:" + res)

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

	fmt.Println("CONFIG:" + string(configJson))
	//quotedStr := configJson
	quotedStr := strings.Trim(strconv.Quote((string(configJson))), `"`)
	fmt.Println("QUOTED:" + string(quotedStr))
	queryStr := fmt.Sprintf(`mutation { createSessionFromJson(input: {config: "%s"}) {sessionToken} }`, quotedStr)

	res, err := c.Query(queryStr)
	if err != nil {
		fmt.Println("Failed to query sever")
		return token, err
	}

	fmt.Println("Response:" + res)

	var gqlResp struct {
		Data struct{ CreateSessionFromJson struct{ SessionToken string } }
	}
	err = json.Unmarshal([]byte(res), &gqlResp)
	if err != nil {
		fmt.Println(err)
		return token, err
	}

	token, err = uuid.Parse(gqlResp.Data.CreateSessionFromJson.SessionToken)
	if err != nil {
		fmt.Println("Could not obtain session token from server")
		return token, err
	}

	return token, nil
}

func (c *Client) createAsset(asset types.Asset, token uuid.UUID) {

	asset.Session = token

	assetJson, err := json.Marshal(asset)
	if err != nil {
		fmt.Println(err)
	}

	var data interface{}
	err = json.Unmarshal(assetJson, &data)
	q := gqlEncoder(data)

	queryStr := fmt.Sprintf(`mutation { createAsset(input:  %s) {id} }`, string(q))

	res, err := c.Query(queryStr)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Response:" + res)
}

// returns Asset objects by converting the contests of config.Scope
func makeAssets(config *config.Config) []*types.Asset {

	assets := convertScopeToAssets(config.Scope)
	for i, asset := range assets {
		asset.Name = fmt.Sprintf("asset#%d", i+1)
	}

	return assets
}

// Converts unmarshalled JSON into graphql field syntax
// This is a simple function for testing
func gqlEncoder(data interface{}) string {
	var q string

	switch data.(type) {
	case map[string]interface{}:
		q += "{"
		for key, val := range data.(map[string]interface{}) {
			q += fmt.Sprintf("%s: %v,", key, gqlEncoder(val))
		}
		q = strings.TrimRight(q, ", ")
		q += "}"
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

// ipnet2Prefix converts a net.IPNet to a netip.Prefix.
func ipnet2Prefix(ipn net.IPNet) netip.Prefix {
	addr, _ := netip.AddrFromSlice(ipn.IP)
	cidr, _ := ipn.Mask.Size()
	return netip.PrefixFrom(addr, cidr)
}

// convertScopeToAssets converts all items in a Scope to a slice of *Asset.
func convertScopeToAssets(scope *config.Scope) []*types.Asset {
	var assets []*types.Asset

	// Convert Domains to assets.
	for _, domain := range scope.Domains {
		fqdn := fqdn.FQDN{Name: domain}
		data := types.AssetData{
			OAMAsset: fqdn,
			OAMType:  fqdn.AssetType(),
		}
		asset := &types.Asset{
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
			data := types.AssetData{
				OAMAsset: asset,
				OAMType:  asset.AssetType(),
			}
			assets = append(assets, &types.Asset{Data: data})
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
		data := types.AssetData{
			OAMAsset: asset,
			OAMType:  asset.AssetType(),
		}
		assets = append(assets, &types.Asset{Data: data})
	}

	// Convert ASNs to assets.
	for _, asn := range scope.ASNs {
		asset := oamNet.AutonomousSystem{Number: asn}
		data := types.AssetData{
			OAMAsset: asset,
			OAMType:  asset.AssetType(),
		}
		assets = append(assets, &types.Asset{Data: data})
	}

	return assets
}
