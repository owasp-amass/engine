// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package archive

import "testing"

func TestWaybackProcess(t *testing.T) {
	data := `[["original"],
	["http://www.utica.edu:80/"],
	["http://www.utica.edu:80/\"target=\"_blank"],
	["http://www.utica.edu:80/%20"],
	["http://www.utica.edu:80/%20/t%20_blank"],
	["https://www.utica.edu/)"],
	["https://www.utica.edu/.well-known/ai-plugin.json"],
	["https://www.utica.edu/.well-known/assetlinks.json"],
	["https://www.utica.edu/.well-known/dnt-policy.txt"],
	["https://www.utica.edu/.well-known/gpc.json"],
	["https://www.utica.edu/.well-known/nodeinfo"],
	["https://www.utica.edu/.well-known/openid-configuration"],
	["https://www.utica.edu/.well-known/security.txt"],
	["https://www.utica.edu/.well-known/trust.txt"],
	["http://www.utica.edu:80/0001/teamstats"],
	["http://www.utica.edu/01/"],
	["http://www.utica.edu:80/0102/teamstats"],
	["http://www.utica.edu:80/0203/teamstats"],
	["http://www.utica.edu:80/0304/teamstats"],
	["http://www.utica.edu:80/0405/teamstats"],
	["http://www.utica.edu:80/0506/teamstats"],
	["http://www.utica.edu:80/0607/teamstats"],
	["http://www.utica.edu:80/0708/teamstats"]]`

	w := NewWayback().(*wayback)
	if subs := w.process(data); len(subs) != 1 || subs[0] != "www.utica.edu" {
		t.Errorf("Wayback process returned %d subdomains", len(subs))
	}
}
