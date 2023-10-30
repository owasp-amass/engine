package types

import (
	"github.com/google/uuid"
	oam "github.com/owasp-amass/open-asset-model"
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
