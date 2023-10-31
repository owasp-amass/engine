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
		fmt.Println(err)
		return token, err
	}

	quotedStr := strings.Trim(strconv.Quote((string(configJson))), `"`)
	queryStr := fmt.Sprintf(`mutation { createSessionFromJson(input: {config: "%s"}) {sessionToken} }`, quotedStr)

	res, err := c.Query(queryStr)
	if err != nil {
		fmt.Println("Failed to query sever")
		return token, err
	}

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

func (c *Client) CreateAsset(asset types.Asset, token uuid.UUID) {

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

func (c *Client) TerminateSession(token uuid.UUID) {
	queryStr := fmt.Sprintf(`mutation { terminateSession(sessionToken: "%s") }`, token.String())
	res, err := c.Query(queryStr)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Response:" + res)
}

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
	defer conn.Close()
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	// Init
	message := fmt.Sprintf(`{"type": "connection_init","id": "%s","payload": {}}`, id)
	err = conn.WriteMessage(websocket.TextMessage, []byte(message))
	if err != nil {
		fmt.Println("Error sending message:", err)
		return nil, err
	}

	// Start the subscription
	message = fmt.Sprintf(`{"type": "start","id":"%s","payload":{"query":"subscription { logMessages(sessionToken: \"%s\")}"} }`, id, token.String())
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
				_, message, err := conn.ReadMessage()
				if err != nil {
					fmt.Println("Error reading message:", err)
					return
				}

				fmt.Printf("Received: %s\n", message)
				ch <- string(message)

				/*
					// send the subscription message
					if strings.Contains(string(message), "ka") {
						message = []byte(`{"type": "start","id":"2","payload":{"query":"subscription { logMessages(sessionToken: \"` + token.String() + `\")}"} }`)
						fmt.Println(string(message))

						err = conn.WriteMessage(websocket.TextMessage, message)
						if err != nil {
							fmt.Println("Error sending message:", err)
						}
					}
				*/
			}
		}

	}()

	return ch, nil
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
