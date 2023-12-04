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
	"github.com/owasp-amass/engine/types"
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

/*
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
*/

func (c *Client) Query(query string) (string, error) {
	quotedStr := strings.Trim(strconv.Quote((string(query))), `"`)
	body := []byte(fmt.Sprintf(`{"query":"%s"}`, quotedStr))

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

// Create a session by sending the config elements as graphql named fields
// TODO: Not Implemented. The transfromations use "->" in the config YAML, but
// that is not a valid field name in GraphQL
func (c *Client) CreateSession(config *config.Config) (uuid.UUID, error) {

	return c.createSessionWithJSON(config)

	/*

		// TODO: handle creating a session through graphql fields instead of JSON object

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
	*/
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

func (c *Client) CreateAsset(asset types.Asset, token uuid.UUID) error {
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

	queryStr := fmt.Sprintf(`mutation { createAsset(input:  %s) {id} }`, string(q))

	res, err := c.Query(queryStr)
	if err != nil {
		return err
	}
	fmt.Println("Response:" + res)
	return nil
}

func (c *Client) TerminateSession(token uuid.UUID) {
	queryStr := fmt.Sprintf(`mutation { terminateSession(sessionToken: "%s") }`, token.String())

	if res, err := c.Query(queryStr); err != nil {
		fmt.Println(res)
	}
}

func (c *Client) SessionStats(token uuid.UUID) (types.SessionStatsResponse, error) {
	queryStr := fmt.Sprintf(`query { sessionStats(sessionToken: "%s"){
		workItemsInProcess 
		workItemsWaiting 
		workItemsProcessable} }`, token.String())

	res, err := c.Query(queryStr)
	if err != nil {
		return types.SessionStatsResponse{}, err
	}

	var gqlResp struct {
		Data struct{ SessionStats types.SessionStatsResponse }
	}
	if err := json.Unmarshal([]byte(res), &gqlResp); err != nil {
		return types.SessionStatsResponse{}, err
	}

	return gqlResp.Data.SessionStats, nil
}

// Creates subscription to receove a stream of log messages from the sever
// https://github.com/enisdenjo/graphql-ws/blob/master/PROTOCOL.md
// Client: {"type": "connection_init","id": "<generated-ID-1>","payload": {}}
// Server: {"type":"connection_ack"}
// Client: {"type": "start","id":"<generated-ID-2>","payload":{"query":"subscription { ... }"} }
// Server: {"payload":{"data":{ ... }},"id":""<generated-ID-2>","type":"data"}
// Server: {"type":"ka"}

func (c *Client) Subscribe(token uuid.UUID) (<-chan string, error) {
	// Connect
	parsedURL, _ := url.Parse(c.url)
	parsedURL.Scheme = "ws"
	id := uuid.New().String()

	conn, _, err := websocket.DefaultDialer.Dial(parsedURL.String(), nil)
	if err != nil {
		fmt.Println("Error connecting to the WebSocket server:", err)
		return nil, err
	}

	c.wsClient = conn

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	// Subprotocol Init
	message := fmt.Sprintf(`{"type": "connection_init","id": "%s","payload": {}}`, id)
	fmt.Println("Message:" + string(message))
	err = conn.WriteMessage(websocket.TextMessage, []byte(message))
	if err != nil {
		fmt.Println("Error sending message:", err)
		return nil, err
	}

	// Start the subscription
	id = uuid.New().String()
	message = fmt.Sprintf(`{"type": "start", "id":"%s", "payload":{"query":"subscription { logMessages(sessionToken: \"%s\")}"} }`, id, token.String())
	fmt.Println("Message:" + string(message))
	err = conn.WriteMessage(websocket.TextMessage, []byte(message))
	if err != nil {
		fmt.Println("Error sending message:", err)
		return nil, err
	}

	ch := make(chan string)

	// Receive go routine
	go func() {
		for {
			select {
			case <-interrupt:
				fmt.Println("Received interrupt signal. Closing WebSocket connection...")
				return
			default:
				mType, message, err := c.wsClient.ReadMessage()
				if err != nil {
					fmt.Printf("Error reading message: %d, %s", mType, err)
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
