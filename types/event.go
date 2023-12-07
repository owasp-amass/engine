// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/google/uuid"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type Event struct {
	Name       string
	Asset      *dbt.Asset
	Dispatcher interface{}
	Session    interface{}
}

type AssetData struct {
	OAMAsset oam.Asset     `json:"asset"`
	OAMType  oam.AssetType `json:"type"`
}

type Asset struct {
	Session uuid.UUID `json:"sessionToken,omitempty"`
	Name    string    `json:"assetName,omitempty"`
	Data    AssetData `json:"data,omitempty"`
}
