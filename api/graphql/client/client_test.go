package client

import (
	"fmt"
	"testing"

	"github.com/owasp-amass/config/config"
)

func TestCreateSession(t *testing.T) {

	c := config.NewConfig()
	err := config.AcquireConfig("", "config.yml", c)
	if err != nil {
		fmt.Println(err) // Handle any errors that occur during configuration acquisition.
	}

	client := NewClient("http://localhost:4000/graphql")

	fmt.Println("right here")
	client.createSession(c)
}

func TestCreateSessionWithJSON(t *testing.T) {

	c := config.NewConfig()
	err := config.AcquireConfig("", "config.yml", c)
	if err != nil {
		fmt.Println(err) // Handle any errors that occur during configuration acquisition.
	}

	client := NewClient("http://localhost:4000/graphql")

	client.createSessionWithJSON(c)
}

func TestCreateAsset(t *testing.T) {

	// We need a an initilaized session before we can create an event

	c := config.NewConfig()
	err := config.AcquireConfig("", "config.yml", c)
	if err != nil {
		fmt.Println(err) // Handle any errors that occur during configuration acquisition.
	}

	client := NewClient("http://localhost:4000/graphql")
	token, _ := client.createSessionWithJSON(c)

	assets := makeAssets(c)

	for _, a := range assets {
		fmt.Printf("%v\n", a)
		client.createAsset(*a, token)
	}

}

func TestSubscribe(t *testing.T) {

	c := config.NewConfig()
	err := config.AcquireConfig("", "config.yml", c)
	if err != nil {
		fmt.Println(err)
	}

	client := NewClient("http://localhost:4000/graphql")
	token, _ := client.createSessionWithJSON(c)

	handler := func(message string) {
		fmt.Println("Received message:", message)
	}

	client.Subscribe(token, handler)
	select {}
}
