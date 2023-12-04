// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"strconv"
	"strings"
	"sync"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
)

type OAMCache struct {
	sync.Mutex
	cache     Cache
	assets    map[string]map[string]*types.Asset
	relations map[string][]*types.Relation
}

func NewOAMCache(c Cache) Cache {
	return &OAMCache{
		cache:     c,
		assets:    make(map[string]map[string]*types.Asset),
		relations: make(map[string][]*types.Relation),
	}
}

func (c *OAMCache) GetAsset(a oam.Asset) (*types.Asset, bool) {
	key := c.getKey(a)
	if key == "" {
		return nil, false
	}

	c.Lock()
	t := string(a.AssetType())
	if m, found := c.assets[t]; found {
		if v, found := m[key]; found {
			c.Unlock()
			return v, true
		}
	}
	c.Unlock()

	if c.cache != nil {
		if v, hit := c.cache.GetAsset(a); v != nil && hit {
			c.SetAsset(v)
			return v, false
		}
	}
	return nil, false
}

func (c *OAMCache) GetAssetsByType(t oam.AssetType) ([]*types.Asset, bool) {
	c.Lock()
	defer c.Unlock()

	var results []*types.Asset
	if set, found := c.assets[string(t)]; found {
		for _, v := range set {
			results = append(results, v)
		}
	}

	if len(results) == 0 {
		return nil, false
	}
	return results, true
}

func (c *OAMCache) SetAsset(a *types.Asset) {
	key := c.getKey(a.Asset)
	if key == "" {
		return
	}

	c.Lock()
	defer c.Unlock()

	t := string(a.Asset.AssetType())
	if _, found := c.assets[t]; !found {
		c.assets[t] = make(map[string]*types.Asset)
	}
	c.assets[t][key] = a
}

func (c *OAMCache) getKey(asset oam.Asset) string {
	var key string

	switch v := asset.(type) {
	case *domain.FQDN:
		key = v.Name
	case *network.IPAddress:
		key = v.Address.String()
	case *network.Netblock:
		key = v.Cidr.String()
	case *network.AutonomousSystem:
		key = strconv.Itoa(v.Number)
	case *network.RIROrganization:
		key = v.Name
	}

	return strings.ToLower(key)
}

func (c *OAMCache) GetRelations(r *types.Relation) ([]*types.Relation, bool) {
	if r.FromAsset == nil && r.ToAsset == nil {
		return nil, false
	}

	c.Lock()
	var relations []*types.Relation
	for _, relation := range c.relations[r.Type] {
		var match bool

		if r.FromAsset != nil && r.ToAsset != nil {
			if r.FromAsset == relation.FromAsset && r.ToAsset == relation.ToAsset {
				match = true
			}
		} else {
			if r.FromAsset == relation.FromAsset {
				match = true
			}
			if r.ToAsset == relation.ToAsset {
				match = true
			}
		}

		if match {
			relations = append(relations, relation)
		}
	}
	c.Unlock()

	if len(relations) > 0 {
		return relations, true
	}

	if c.cache != nil {
		if rels, hit := c.cache.GetRelations(r); hit && len(rels) > 0 {
			for _, relation := range rels {
				c.SetRelation(relation)
			}
			return rels, false
		}
	}
	return nil, false
}

func (c *OAMCache) SetRelation(r *types.Relation) {
	c.Lock()
	defer c.Unlock()

	c.relations[r.Type] = append(c.relations[r.Type], r)
}
