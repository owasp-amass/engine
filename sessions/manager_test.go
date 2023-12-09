// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"io"
	"log"
	"testing"
)

func TestAddSession001(t *testing.T) {
	l := log.New(io.Discard, "T", log.Lmicroseconds)
	mgr := NewManager(l)
	defer mgr.Shutdown()

	s := &Session{}
	id, err := mgr.AddSession(s)
	if err != nil {
		t.Error(err)
	}

	if id == zeroSessionUUID {
		t.Error("Session ID is zero")
	}
}
