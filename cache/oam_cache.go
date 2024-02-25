// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
)

type relations struct {
	all   []*types.Relation
	froms []*types.Relation
	tos   []*types.Relation
}

type OAMCache struct {
	sync.Mutex
	cache     Cache
	assets    map[string]map[string]*types.Asset
	relations map[string]*relations
}

func NewOAMCache(c Cache) Cache {
	return &OAMCache{
		cache:     c,
		assets:    make(map[string]map[string]*types.Asset),
		relations: make(map[string]*relations),
	}
}

func (c *OAMCache) Close() {
	c.Lock()
	defer c.Unlock()

	if c.cache != nil {
		c.cache.Close()
	}

	for k := range c.assets {
		clear(c.assets[k])
	}
	clear(c.assets)
	clear(c.relations)
}

func (c *OAMCache) GetAsset(a oam.Asset) (*types.Asset, bool) {
	key := getKey(a)
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
	key := getKey(a.Asset)
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

func (c *OAMCache) GetRelations(r *types.Relation) ([]*types.Relation, bool) {
	if c.relations[r.Type] == nil || (r.FromAsset == nil && r.ToAsset == nil) {
		return nil, false
	}

	c.Lock()
	var relations []*types.Relation
	if r.FromAsset != nil && r.ToAsset == nil && len(c.relations[r.Type].froms) > 0 {
		fromstr := getKey(r.FromAsset.Asset)
		relations = append(relations, searchRelations(fromstr, c.relations[r.Type].froms, true)...)
	} else if r.FromAsset == nil && r.ToAsset != nil && len(c.relations[r.Type].tos) > 0 {
		tostr := getKey(r.ToAsset.Asset)
		relations = append(relations, searchRelations(tostr, c.relations[r.Type].tos, false)...)
	} else {
		for _, rel := range c.relations[r.Type].all {
			if r.FromAsset == rel.FromAsset && r.ToAsset == rel.ToAsset {
				relations = append(relations, rel)
			}
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

func (c *OAMCache) GetRelationsByType(rtype string) ([]*types.Relation, bool) {
	c.Lock()
	defer c.Unlock()

	if r := c.relations[rtype]; len(r.all) > 0 {
		return r.all, true
	}
	return nil, false
}

func (c *OAMCache) SetRelation(r *types.Relation) {
	c.Lock()
	defer c.Unlock()

	if _, found := c.relations[r.Type]; !found {
		c.relations[r.Type] = new(relations)
	}

	c.relations[r.Type].all = append(c.relations[r.Type].all, r)
	c.relations[r.Type].froms = sortRelations(append(c.relations[r.Type].froms, r), true)
	c.relations[r.Type].tos = sortRelations(append(c.relations[r.Type].tos, r), false)
}

func getKey(asset oam.Asset) string {
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

func sortRelations(rels []*types.Relation, from bool) []*types.Relation {
	sort.Slice(rels, func(i, j int) bool {
		if from {
			return getKey(rels[i].FromAsset.Asset) < getKey(rels[j].FromAsset.Asset)
		}
		return getKey(rels[i].ToAsset.Asset) < getKey(rels[j].ToAsset.Asset)
	})
	return rels
}

func searchRelations(key string, rels []*types.Relation, from bool) []*types.Relation {
	rlen := len(rels)

	i := sort.Search(rlen, func(i int) bool {
		if from {
			return getKey(rels[i].FromAsset.Asset) >= key
		}
		return getKey(rels[i].ToAsset.Asset) >= key
	})
	if i >= rlen {
		return nil
	}

	asset := rels[i].ToAsset.Asset
	if from {
		asset = rels[i].FromAsset.Asset
	}
	if getKey(asset) != key {
		return nil
	}

	var results []*types.Relation
	for _, rel := range rels[i:] {
		if from && getKey(rel.FromAsset.Asset) != key {
			break
		} else if !from && getKey(rel.ToAsset.Asset) != key {
			break
		}
		results = append(results, rel)
	}
	return results
}
