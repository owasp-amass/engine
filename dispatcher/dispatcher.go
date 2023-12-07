// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"errors"
	"log"
	"os"

	"github.com/caffix/queue"
	"github.com/owasp-amass/engine/registry"
	"github.com/owasp-amass/engine/sessions"
	et "github.com/owasp-amass/engine/types"
)

func NewDispatcher(l *log.Logger, r *registry.Registry, mgr *sessions.Manager) *Dispatcher {
	if l == nil {
		l = log.New(os.Stdout, "", log.LstdFlags)
	}

	d := &Dispatcher{
		Queue:     queue.NewQueue(),
		Log:       l,
		reg:       r,
		mgr:       mgr,
		done:      make(chan struct{}),
		completed: make(chan *registry.EventDataElement, 100),
	}

	go d.collectEvents()
	return d
}

func (d *Dispatcher) Shutdown() {
	d.Queue.Process(func(interface{}) {})
}

func (d *Dispatcher) collectEvents() {
	for {
		select {
		case <-d.done:
			return
		case ede := <-d.completed:
			if element := <-ede.Ch; element != nil {
				if err := element.Error; err != nil {
					d.Log.Printf("%s: %v", ede.Event.Name, err)
				}
				// increment the number of events processed in the session
				go func(ede *registry.EventDataElement) {
					if session, ok := ede.Event.Session.(*sessions.Session); ok {
						session.Lock()
						session.Stats.WorkItemsCompleted++
						session.Unlock()
					}
				}(ede)
			}
		}
	}
}

func (d *Dispatcher) DispatchEvent(e *et.Event) error {
	if e == nil {
		return errors.New("the event is nil")
	}

	a := e.Asset.Asset
	session := e.Session.(*sessions.Session)
	// Do not schedule the same asset more than once
	if p, hit := session.Cache.GetAsset(a); p != nil && hit {
		return errors.New("this event has been scheduled previously")
	}

	ap, err := d.reg.GetPipeline(a.AssetType())
	if err != nil {
		return err
	}

	if data := d.reg.NewEventDataElement(e); data != nil {
		session.Cache.SetAsset(e.Asset)
		data.Ch = d.completed
		ap.Queue.Append(data)
		// increment the number of events processed in the session
		go func(ede *registry.EventDataElement) {
			if session, ok := ede.Event.Session.(*sessions.Session); ok {
				session.Lock()
				session.Stats.WorkItemsTotal++
				session.Unlock()
			}
		}(data)
	}
	return nil
}
