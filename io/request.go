package io

import (
	oam "github.com/owasp-amass/open-asset-model"
)

type Request interface {
	SourceAsset() oam.Asset
	Type() string
}
