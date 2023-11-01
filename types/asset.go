package types

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	oam "github.com/owasp-amass/open-asset-model"
	oamContact "github.com/owasp-amass/open-asset-model/contact"
	fqdn "github.com/owasp-amass/open-asset-model/domain"
	oamNet "github.com/owasp-amass/open-asset-model/network"
	oamOrg "github.com/owasp-amass/open-asset-model/org"
	oamPeople "github.com/owasp-amass/open-asset-model/people"
	oamWHOIS "github.com/owasp-amass/open-asset-model/whois"
)

type Asset struct {
	Session uuid.UUID `json:"sessionToken,omitempty"`
	Name    string    `json:"assetName,omitempty"`
	Data    AssetData `json:"data,omitempty"`
}

type AssetData struct {
	OAMAsset oam.Asset     `json:"asset"`
	OAMType  oam.AssetType `json:"type"`
}

func (d *AssetData) UnmarshalJSON(data []byte) error {
	// First, unmarshal to a temporary struct to get the AssetType without unmarshalling the asset itself
	var tmp struct {
		OAMType  oam.AssetType   `json:"type"`
		RawAsset json.RawMessage `json:"asset"` // Capture the asset as raw JSON
	}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	// Populate the known fields

	d.OAMType = tmp.OAMType

	// Based on the AssetType, we'll unmarshal the RawAsset into the appropriate struct
	switch tmp.OAMType {
	case oam.IPAddress:
		var asset oamNet.IPAddress
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.Netblock:
		var asset oamNet.Netblock
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.ASN:
		var asset oamNet.AutonomousSystem
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.RIROrg:
		var asset oamNet.RIROrganization
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.FQDN:
		var asset fqdn.FQDN
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.WHOIS:
		var asset oamWHOIS.WHOIS
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.Location:
		var asset oamContact.Location
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.Phone:
		var asset oamContact.Phone
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.Email:
		var asset oamContact.EmailAddress
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.Person:
		var asset oamPeople.Person
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.Organization, oam.Registrant:
		var asset oamOrg.Organization
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.Registrar:
		var asset oamWHOIS.Registrar
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	default:
		return fmt.Errorf("unknown or unsupported asset type: %s", tmp.OAMType)
	}

	return nil
}
