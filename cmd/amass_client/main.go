package main

// Client example that utilizes the API and new Amass engine

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"time"

	pb "github.com/cheggaaa/pb/v3"
	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/engine/api/graphql/client"
	"github.com/owasp-amass/engine/types"
	fqdn "github.com/owasp-amass/open-asset-model/domain"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

func main() {
	c := config.NewConfig()
	// Load config from file
	if err := config.AcquireConfig("", "./api/graphql/client/config.yml", c); err != nil {
		fmt.Println(err)
	}

	// TODO: Parse commandline flags
	// connect to amass-engine
	client := client.NewClient("http://localhost:4000/graphql")
	token, _ := client.CreateSession(c)

	// Create interrupt channel and subscribe to server log messages
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	messages, err := client.Subscribe(token)
	if err != nil {
		fmt.Println(err)
	}

	var count int
	for _, a := range makeAssets(c) {
		fmt.Printf("%v\n", a)
		if err := client.CreateAsset(*a, token); err == nil {
			count++
		}
	}

	fmt.Printf("\nSession Progress:\n")
	progress := pb.Start64(int64(count))
	done := make(chan struct{})
	go func() {
		var finished int
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()

		for {
			select {
			case <-t.C:
				if stats, err := client.SessionStats(token); err == nil {
					progress.SetTotal(int64(stats.WorkItemsTotal))
					progress.SetCurrent(int64(stats.WorkItemsCompleted))
					if stats.WorkItemsCompleted == stats.WorkItemsTotal {
						finished++
						if finished == 5 {
							close(done)
						}
					}
				}
			case message := <-messages:
				fmt.Fprint(io.Discard, message)
			case <-done:
				return
			}
		}
	}()

	// Terminate client session
loop:
	for {
		select {
		case <-done:
			break loop
		case <-interrupt:
			close(done)
		}
	}
	client.TerminateSession(token)
}

// Below are helper functions for converting an Amass config / scope into OAM assets
const (
	ipv4 = "IPv4"
	ipv6 = "IPv6"
)

// returns Asset objects by converting the contests of config.Scope
func makeAssets(config *config.Config) []*types.Asset {
	assets := convertScopeToAssets(config.Scope)

	for i, asset := range assets {
		asset.Name = fmt.Sprintf("asset#%d", i+1)
	}

	return assets
}

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
			asset := oamnet.IPAddress{Address: addr, Type: ipType}
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
		asset := oamnet.Netblock{Cidr: prefix, Type: ipType}
		data := types.AssetData{
			OAMAsset: asset,
			OAMType:  asset.AssetType(),
		}
		assets = append(assets, &types.Asset{Data: data})
	}

	// Convert ASNs to assets.
	for _, asn := range scope.ASNs {
		asset := oamnet.AutonomousSystem{Number: asn}
		data := types.AssetData{
			OAMAsset: asset,
			OAMType:  asset.AssetType(),
		}
		assets = append(assets, &types.Asset{Data: data})
	}

	return assets
}
