// Copyright © by Jeff Foley 2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"strconv"
	"strings"
	"testing"
)

func TestPassiveDNSFilterInsert(t *testing.T) {
	pdnsf := NewPassiveDNSFilter()
	defer pdnsf.Close()

	fqdn := "www.cs.utica.edu"
	pdnsf.Insert(fqdn)

	cur := pdnsf
	labels := strings.Split(fqdn, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		if _, found := cur[labels[i]]; !found {
			t.Errorf("Passive DNS Filter Insert failed for label %s at index %d", labels[i], i)
			break
		}
		if i > 0 {
			cur = cur[labels[i]].(PassiveDNSFilter)
		}
	}
}

func TestPassiveDNSFilterPrune(t *testing.T) {
	pdnsf := NewPassiveDNSFilter()
	defer pdnsf.Close()

	for i := 0; i < 200; i++ {
		fqdn := "www" + strconv.Itoa(i) + ".cs.utica.edu"
		pdnsf.Insert(fqdn)
	}

	var found bool
	var name string
	for _, fqdn := range pdnsf.Slice() {
		if fqdn == "www1.cs.utica.edu" {
			name = fqdn
			found = true
			break
		}
	}

	if found {
		t.Errorf("Passive DNS Filter Prune failed to remove the labels: %s", name)
	}
}

func TestPassiveDNSFilterSlice(t *testing.T) {
	pdnsf := NewPassiveDNSFilter()
	defer pdnsf.Close()

	fqdn := "www.cs.utica.edu"
	pdnsf.Insert(fqdn)

	if fqdn != pdnsf.Slice()[0] {
		t.Errorf("Passive DNS Filter Slice failed to produce the expected FQDN: %s", fqdn)
	}
}
