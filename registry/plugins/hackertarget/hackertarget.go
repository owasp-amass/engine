package hackertarget

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	DBtypes "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/registry"
	"github.com/owasp-amass/engine/scheduler"
	"github.com/owasp-amass/engine/sessions"
	engineTypes "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamDom "github.com/owasp-amass/open-asset-model/domain"
	oamNet "github.com/owasp-amass/open-asset-model/network"
)

// Base URL for the HackerTarget API used for domain lookups.
const (
	apiBaseURL = "https://api.hackertarget.com/hostsearch/?q="
	ipv4       = "IPv4"
	ipv6       = "IPv6"
	asnBaseURL = "https://api.hackertarget.com/aslookup/?q="
)

var AmassPlugin HackerTargetPlugin

type HackerTargetPlugin struct{}

func (p *HackerTargetPlugin) Start(r *registry.Registry) error {
	// Register the handler
	r.RegisterHandler(
		registry.Handler{
			Name:       "HackerTarget-Subdomain-IPHandler",
			Transforms: []string{"fqdn", "ipaddress"},
			EventType:  oam.FQDN, //from is FQDN
			Handler:    p.lookupDomain,
		})
	r.RegisterHandler(
		registry.Handler{
			Name:       "HackerTarget-IPHandler",
			Transforms: []string{"netblock", "asn", "rirorg"},
			EventType:  oam.IPAddress, //from is IP
			Handler:    p.ipLookup,
		})
	return nil
}

// lookupDomain determines what type of lookups (subdomain or IP) should be performed
// based on the event's session configuration.
//
// Parameters:
// - e: The event containing relevant session information.
//
// Returns:
// - error: Any error encountered during the lookup.
func (p *HackerTargetPlugin) lookupDomain(e *engineTypes.Event) error {
	// get session config and look at the tansforms to determine the type of events generated
	session := e.Session.(*sessions.Session)
	// Extract transformation rules from the session configuration.
	transforms := session.Cfg.Transformations
	// Flags to determine the type of lookup required.
	var ipSwitch, subdomainSwitch bool

	// Iterate over each transformation rule.
	for _, transform := range transforms {
		// Convert transformation source and target types to lowercase.
		fromLower := strings.ToLower(transform.From)
		toLower := strings.ToLower(transform.To)

		// Check if the transformation is for Fully Qualified Domain Names (FQDNs).
		if fromLower == "fqdn" {
			// Set the corresponding flag based on the transformation target.
			switch toLower {
			case "ipaddress":
				ipSwitch = true
			case "fqdn":
				subdomainSwitch = true
			case "all":
				// If transformation target is "all", set both flags but check exclusions.
				ipSwitch = true
				subdomainSwitch = true
				for _, e := range transform.Exclude {
					e = strings.ToLower(e)
					if e == "fqdn" {
						subdomainSwitch = false
					}
					if e == "ipaddress" {
						ipSwitch = false
					}
				}
			}
		}
	}

	return lookupdomain(e, subdomainSwitch, ipSwitch)
}

// ipLookup determines what type of IP-related lookups (netblock, ASN, or RIR) should be performed
// based on the event's session configuration.
//
// Parameters:
// - e: The event containing relevant session information.
//
// Returns:
// - error: Any error encountered during the lookup.
func (p *HackerTargetPlugin) ipLookup(e *engineTypes.Event) error {
	// get session config and look at the tansforms to determine the type of events generated
	session := e.Session.(*sessions.Session)
	// Extract transformation rules from the session configuration.
	transforms := session.Cfg.Transformations
	// Flags to determine the type of lookup required.
	var netblockSwitch, asnSwitch, rirSwitch bool

	// Iterate over each transformation rule.
	for _, transform := range transforms {
		// Convert transformation source and target types to lowercase.
		fromLower := strings.ToLower(transform.From)
		toLower := strings.ToLower(transform.To)

		// Check if the transformation is for IP addresses.
		if fromLower == "ipaddress" {
			// Set the corresponding flag based on the transformation target.
			switch toLower {
			case "netblock":
				netblockSwitch = true
			case "asn":
				asnSwitch = true
			case "rirorg":
				rirSwitch = true
			case "all":
				// If transformation target is "all", set all flags but check exclusions.
				netblockSwitch = true
				asnSwitch = true
				rirSwitch = true
				for _, e := range transform.Exclude {
					e = strings.ToLower(e)
					if e == "netblock" {
						netblockSwitch = false
					}
					if e == "asn" {
						asnSwitch = false
					}
					if e == "rirorg" {
						rirSwitch = false
					}
				}
			}
		}
	}

	return iplookup(e, netblockSwitch, asnSwitch, rirSwitch)
}

// newAsset function converts a given name to an appropriate asset type.
// This function serves as a helper to abstract the details of asset creation.
func newAsset(name string, assetType oam.AssetType) (oam.Asset, error) {
	var iptype string
	switch assetType {
	case oam.IPAddress:
		// For IP addresses, we need to determine their type (IPv4/IPv6).
		ipAddr, err := netip.ParseAddr(name)
		if err != nil {
			return nil, err
		}
		if ipAddr.Is4() {
			iptype = ipv4
		} else if ipAddr.Is6() {
			iptype = ipv6
		} else {
			return nil, fmt.Errorf("invalid ip type")
		}
		return oamNet.IPAddress{Address: ipAddr, Type: iptype}, nil
	case oam.FQDN:
		return oamDom.FQDN{Name: name}, nil
	case oam.ASN:
		asn, err := strconv.Atoi(name)
		if err != nil {
			return nil, err
		}
		return oamNet.AutonomousSystem{Number: asn}, nil
	case oam.Netblock:
		netCIDR := netip.MustParsePrefix(name)
		// Determine the IP type based on the address characteristics.
		addr := netCIDR.Addr()
		if addr.Is4In6() {
			iptype = ipv4
		} else if addr.Is6() {
			iptype = ipv6
		} else {
			iptype = ipv4
		}
		return oamNet.Netblock{Cidr: netCIDR, Type: iptype}, nil
	case oam.RIROrg:
		return oamNet.RIROrganization{Name: name}, nil
	default:
		return nil, fmt.Errorf("invalid asset type")
	}
}

// LookupDomain function queries the HackerTarget API for subdomains and IPs related to a root domain.
func lookupdomain(e *engineTypes.Event, subdomainSwitch, ipSwitch bool) error {
	// Extracting the root domain from the event data.
	rootDomain := e.Data.(engineTypes.AssetData).OAMAsset.(oamDom.FQDN).Name

	// Casting scheduler and session from the event.
	scheduler := e.Sched.(*scheduler.Scheduler)
	session := e.Session.(*sessions.Session)

	// Constructing the full API URL.
	url := apiBaseURL + rootDomain

	// Making an HTTP GET request to the API.
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("error fetching URL: %w", err)
	}
	// Ensuring the response body is closed once done.
	defer resp.Body.Close()

	// Initializing a CSV reader with the response body.
	reader := csv.NewReader(resp.Body)
	// Reading all records from the CSV response.
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("error parsing CSV: %w", err)
	}

	var sDB *DBtypes.Asset

	// Looping through each record from the CSV.
	for _, record := range records {
		// Skip records with insufficient data.
		if len(record) < 2 {
			continue
		}

		// Extract subdomain and IP from the current record.
		subdomain := record[0]
		ip := record[1]

		// If the subdomain is not in scope, skip it.
		if !session.Cfg.IsDomainInScope(subdomain) {
			continue
		}

		// If the subdomain switch is turned on, process subdomains.
		if subdomainSwitch {

			// Create and send an event for the subdomain.
			subdomainEvent, err := newEvent(subdomain, e, oam.FQDN)
			if err != nil {
				return fmt.Errorf("failed to create new event: %v", err)
			}
			scheduler.Schedule(subdomainEvent)

			// Convert subdomain string to asset.
			subAsset, err := newAsset(subdomain, oam.FQDN)
			if err != nil {
				return fmt.Errorf("failed to create an asset: %v", err)
			}
			// Store the subdomain asset in the database.
			sDB, err = session.DB.Create(nil, "", subAsset)
			if err != nil {
				return fmt.Errorf("failed to store in db: %v", err)
			}

		}

		// If the IP switch is turned on, process IPs.
		if ipSwitch {

			// Create and send an event for the IP.
			ipEvent, err := newEvent(ip, e, oam.IPAddress)
			if err != nil {
				return fmt.Errorf("failed to create new event: %v", err)
			}
			scheduler.Schedule(ipEvent)

			// Convert IP string to asset.
			ipAsset, err := newAsset(ip, oam.IPAddress)
			if err != nil {
				return fmt.Errorf("failed to create an asset: %v", err)
			}
			// Depending on the subdomain switch, store the IP asset in the database appropriately.
			if subdomainSwitch {
				_, err = session.DB.Create(sDB, "a_record", ipAsset)
			} else {
				_, err = session.DB.Create(nil, "", ipAsset)
			}
			if err != nil {
				return fmt.Errorf("failed to store in db: %v", err)
			}
		}

	}

	return nil
}

// IpLookup function queries the HackerTarget API using an IP address
// to retrieve related ASN, netblock, and RIR details.
func iplookup(e *engineTypes.Event, netblockSwitch, asnSwitch, rirSwitch bool) error {

	// Grab the asset of the data.
	ipAsset := e.Data.(engineTypes.AssetData).OAMAsset

	// Casting scheduler and session from the event.
	scheduler := e.Sched.(*scheduler.Scheduler)
	session := e.Session.(*sessions.Session)

	// Extract the IP from the event data.
	ip := ipAsset.(oamNet.IPAddress).Address.String()

	// Construct the URL for the API call.
	url := asnBaseURL + ip

	// Make the API call.
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("error fetching URL: %w", err)
	}
	defer resp.Body.Close()

	// Parse the response using the CSV reader.
	reader := csv.NewReader(resp.Body)
	record, err := reader.Read()
	if err != nil {
		return fmt.Errorf("error parsing CSV: %w", err)
	}

	// Ensure the record contains the necessary details (ASN, netblock, RIR).
	if len(record) < 4 {
		return fmt.Errorf("received insufficient data from ASN lookup")
	}
	// Extract ASN, netblock, and RIR details from the record.
	asn, netblock, rirName := record[1], record[2], record[3]

	var iDB *DBtypes.Asset // Placeholder for storing the database asset reference.
	// used as source asset when creating.

	// If the asnSwitch is true, process and store the ASN details.
	if asnSwitch {
		asnAsset, err := newAsset(asn, oam.ASN) // Convert the ASN to its respective asset type.
		if err != nil {
			return fmt.Errorf("failed to create an ASN asset: %v", err)
		}

		// Create the event and schedule it.
		asnEvent, err := newEvent(asn, e, oam.ASN)
		if err != nil {
			return fmt.Errorf("failed to create new event: %v", err)
		}
		err = scheduler.Schedule(asnEvent)
		if err != nil {
			return fmt.Errorf("failed to schedule event: %v", err)
		}

		// Store the ASN asset in the database.
		iDB, err = session.DB.Create(nil, "", asnAsset)
		if err != nil {
			return fmt.Errorf("failed to store ASN in db: %v", err)
		}
	}

	// If the rirSwitch is true, process and store the RIR details.
	if rirSwitch {
		rirAsset, err := newAsset(rirName, oam.RIROrg) // Convert the RIR name to its respective asset type.
		if err != nil {
			return fmt.Errorf("failed to create a RIR asset: %v", err)
		}

		// Create the event and schedule it.
		rirEvent, err := newEvent(rirName, e, oam.RIROrg)
		if err != nil {
			return fmt.Errorf("failed to create new event: %v", err)
		}
		err = scheduler.Schedule(rirEvent)
		if err != nil {
			return fmt.Errorf("failed to schedule event: %v", err)
		}

		// Store the RIR asset in the database and relate it to the ASN if available.
		if asnSwitch {
			_, err = session.DB.Create(iDB, "managed_by", rirAsset)
		} else {
			_, err = session.DB.Create(nil, "", rirAsset)
		}
		if err != nil {
			return fmt.Errorf("failed to store RIR in db: %v", err)
		}
	}

	// If the netblockSwitch is true, process and store the netblock details.
	if netblockSwitch {
		netblockAsset, err := newAsset(netblock, oam.Netblock) // Convert the netblock to its respective asset type.
		if err != nil {
			return fmt.Errorf("failed to create a netblock asset: %v", err)
		}

		// Create the event and schedule it.
		netblockEvent, err := newEvent(netblock, e, oam.Netblock)
		if err != nil {
			return fmt.Errorf("failed to create new event: %v", err)
		}
		err = scheduler.Schedule(netblockEvent)
		if err != nil {
			return fmt.Errorf("failed to schedule event: %v", err)
		}

		// Store the netblock asset in the database and relate it to the ASN if available.
		if asnSwitch {
			iDB, err = session.DB.Create(iDB, "announces", netblockAsset)
		} else {
			iDB, err = session.DB.Create(nil, "", netblockAsset)
		}
		if err != nil {
			return fmt.Errorf("failed to store netblock in db: %v", err)
		}
		// Relate the provided IP to the netblock.
		_, err = session.DB.Create(iDB, "contains", ipAsset)
		if err != nil {
			return fmt.Errorf("failed to store ip in db: %v", err)
		}
	} else {
		// Store the IP in the database if not processing netblock details.
		_, err = session.DB.Create(nil, "", ipAsset)
		if err != nil {
			return fmt.Errorf("failed to store ip in db: %v", err)
		}
	}

	return nil
}

// newEvent function creates a new event based on a provided asset name, asset type,
// and an existing old event for context.
func newEvent(assetName string, oldEvent *engineTypes.Event, newType oam.AssetType) (*engineTypes.Event, error) {
	// Initializing a new event structure with some fields from the old event.
	sampleEvent := &engineTypes.Event{
		SessionID: oldEvent.SessionID,            // Using the UUID from the old event.
		Name:      "HackerTarget: " + assetName,  // Naming the event with a prefix.
		Type:      engineTypes.EventTypeAsset,    // Setting the event type as an asset.
		State:     engineTypes.EventStateDefault, // Default state for the event.
	}
	var iptype string

	// Determine the asset type and populate the event data accordingly.
	switch newType {
	case oam.IPAddress:
		ipAddr, err := netip.ParseAddr(assetName)
		if err != nil {
			return nil, err
		}
		if ipAddr.Is4() {
			iptype = "ipv4"
		} else {
			iptype = "ipv6"
		}
		sampleEvent.Data = engineTypes.AssetData{
			OAMAsset: oamNet.IPAddress{Address: ipAddr, Type: iptype},
			OAMType:  oam.IPAddress,
		}

	case oam.FQDN:
		sampleEvent.Data = engineTypes.AssetData{
			OAMAsset: oamDom.FQDN{Name: assetName},
			OAMType:  oam.FQDN,
		}

	case oam.ASN:
		asn, err := strconv.Atoi(assetName)
		if err != nil {
			return nil, err
		}
		sampleEvent.Data = engineTypes.AssetData{
			OAMAsset: oamNet.AutonomousSystem{Number: asn},
			OAMType:  oam.ASN,
		}

	case oam.Netblock:
		netCIDR := netip.MustParsePrefix(assetName)
		addr := netCIDR.Addr()
		if addr.Is4In6() {
			iptype = "ipv4"
		} else if addr.Is6() {
			iptype = "ipv6"
		} else {
			iptype = "ipv4"
		}
		sampleEvent.Data = engineTypes.AssetData{
			OAMAsset: oamNet.Netblock{Cidr: netCIDR, Type: iptype},
			OAMType:  oam.Netblock,
		}

	case oam.RIROrg:
		sampleEvent.Data = engineTypes.AssetData{
			OAMAsset: oamNet.RIROrganization{Name: assetName},
			OAMType:  oam.RIROrg,
		}

	default:
		return nil, fmt.Errorf("invalid asset type")
	}

	return sampleEvent, nil
}
