// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"log"

	"github.com/caffix/queue"
	"github.com/owasp-amass/engine/registry"
	"github.com/owasp-amass/engine/sessions"
)

type Dispatcher struct {
	Log       *log.Logger
	Queue     queue.Queue
	reg       *registry.Registry
	mgr       *sessions.Manager
	done      chan struct{}
	completed queue.Queue
}
