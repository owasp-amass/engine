package client

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/engine/types"
	oamNet "github.com/owasp-amass/open-asset-model/network"
)

func TestCreateSession(t *testing.T) {

	c := config.NewConfig()
	err := config.AcquireConfig("", "config.yml", c)
	if err != nil {
		fmt.Println(err) // Handle any errors that occur during configuration acquisition.
	}

	client := NewClient("http://localhost:4000/graphql")

	client.CreateSession(c)
	if err != nil {
		fmt.Println(err)
	}
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

	addr, _ := netip.ParseAddr("192.168.0.1")
	asset := oamNet.IPAddress{Address: addr, Type: "IPv4"}
	data := types.AssetData{
		OAMAsset: asset,
		OAMType:  asset.AssetType(),
	}

	a := types.Asset{
		Session: token, Name: "Asset#1", Data: data,
	}

	client.CreateAsset(a, token)
}

func TestSubscribe(t *testing.T) {

	c := config.NewConfig()
	err := config.AcquireConfig("", "config.yml", c)
	if err != nil {
		fmt.Println(err)
	}

	client := NewClient("http://localhost:4000/graphql")
	token, _ := client.createSessionWithJSON(c)

	/*
		handler := func(message string) {
			fmt.Println("Received message:", message)
		}
	*/
	ch, err := client.Subscribe(token)
	m := <-ch
	fmt.Println(m)
	select {}
}
