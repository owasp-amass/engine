// This is a very simple GraphQL client for testing
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/owasp-amass/config/config"
	et "github.com/owasp-amass/engine/types"
)

type Handler func(message string)

type Client struct {
	url        string
	httpClient http.Client
	wsClient   *websocket.Conn
}

func NewClient(url string) *Client {
	httpClient := &http.Client{}

	return &Client{url: url, httpClient: *httpClient}
}

func (c *Client) Query(query string) (string, error) {
	quotedStr := strings.Trim(strconv.Quote((string(query))), `"`)
	b := []byte(fmt.Sprintf(`{"query":"%s"}`, quotedStr))

	req, err := http.NewRequest(http.MethodPost, c.url, bytes.NewBuffer(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return "error", err
	}
	return string(body), nil
}

// Create a session by sending the config elements as graphql named fields
// TODO: Not Implemented. The transfromations use "->" in the config YAML, but
// that is not a valid field name in GraphQL
func (c *Client) CreateSession(config *config.Config) (uuid.UUID, error) {
	return c.createSessionWithJSON(config)
}

func (c *Client) createSessionWithJSON(config *config.Config) (uuid.UUID, error) {
	var token uuid.UUID
	configJson, err := json.Marshal(config)
	if err != nil {
		return token, err
	}

	quotedStr := strings.Trim(strconv.Quote((string(configJson))), `"`)
	queryStr := fmt.Sprintf(`mutation { createSessionFromJson(input: {config: "%s"}) {sessionToken} }`, quotedStr)

	res, err := c.Query(queryStr)
	if err != nil {
		return token, err
	}

	var gqlResp struct {
		Data struct{ CreateSessionFromJson struct{ SessionToken string } }
	}
	if err := json.Unmarshal([]byte(res), &gqlResp); err != nil {
		return token, err
	}

	token, err = uuid.Parse(gqlResp.Data.CreateSessionFromJson.SessionToken)
	if err != nil {
		return token, err
	}
	return token, nil
}

func (c *Client) CreateAsset(asset et.Asset, token uuid.UUID) error {
	asset.Session = token
	assetJson, err := json.Marshal(asset)
	if err != nil {
		return err
	}

	var data interface{}
	if err := json.Unmarshal(assetJson, &data); err != nil {
		return err
	}
	q := gqlEncoder(data)

	queryStr := fmt.Sprintf(`mutation { createAsset(input: %s) {id} }`, string(q))
	if _, err := c.Query(queryStr); err != nil {
		return err
	}
	return nil
}

func (c *Client) TerminateSession(token uuid.UUID) {
	_, _ = c.Query(fmt.Sprintf(`mutation { terminateSession(sessionToken: "%s") }`, token.String()))
}

func (c *Client) SessionStats(token uuid.UUID) (*et.SessionStats, error) {
	queryStr := fmt.Sprintf(`query { sessionStats(sessionToken: "%s"){
		WorkItemsCompleted 
		WorkItemsTotal} }`, token.String())

	res, err := c.Query(queryStr)
	if err != nil {
		return &et.SessionStats{}, err
	}

	var gqlResp struct {
		Data struct{ SessionStats et.SessionStats }
	}
	if err := json.Unmarshal([]byte(res), &gqlResp); err != nil {
		return &et.SessionStats{}, err
	}
	return &gqlResp.Data.SessionStats, nil
}

// Creates subscription to receove a stream of log messages from the sever
func (c *Client) Subscribe(token uuid.UUID) (<-chan string, error) {
	parsedURL, _ := url.Parse(c.url)
	parsedURL.Scheme = "ws"
	id := uuid.New().String()

	conn, _, err := websocket.DefaultDialer.Dial(parsedURL.String(), nil)
	if err != nil {
		return nil, err
	}
	c.wsClient = conn

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	// Subprotocol Init
	message := fmt.Sprintf(`{"type": "connection_init","id": "%s","payload": {}}`, id)
	err = conn.WriteMessage(websocket.TextMessage, []byte(message))
	if err != nil {
		return nil, err
	}

	// Start the subscription
	id = uuid.New().String()
	message = fmt.Sprintf(`{"type": "start", "id":"%s", "payload":{"query":"subscription { logMessages(sessionToken: \"%s\")}"} }`, id, token.String())
	err = conn.WriteMessage(websocket.TextMessage, []byte(message))
	if err != nil {
		return nil, err
	}

	ch := make(chan string)
	// Receive go routine
	go func() {
		for {
			select {
			case <-interrupt:
				return
			default:
				_, message, err := c.wsClient.ReadMessage()
				if err != nil {
					return
				}
				ch <- string(message)
			}
		}
	}()
	return ch, nil
}

// Converts unmarshalled JSON into graphql field syntax
// This is a simple function for testing
func gqlEncoder(data interface{}) string {
	var q string

	switch data := data.(type) {
	case map[string]interface{}:
		q += "{"
		for key, val := range data {
			q += fmt.Sprintf("%s: %v,", key, gqlEncoder(val))
		}
		q = strings.TrimRight(q, ", ")
		q += "}"
	case []interface{}:
		q += "["
		for _, val := range data {
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
