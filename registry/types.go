// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"log"
	"sync"

	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type Registry struct {
	sync.RWMutex
	Log       *log.Logger
	handlers  map[string]map[int][]*Handler
	pipelines map[string]*AssetPipeline
}

type Handler struct {
	Name       string
	Priority   int
	EventType  oam.AssetType
	Transforms []string
	Handler    func(*et.Event) error
}

type EventDataElement struct {
	Event *et.Event
	Error error
	Ch    chan *EventDataElement
}

type PipelineQueue struct {
	queue.Queue
}

type AssetPipeline struct {
	Pipeline *pipeline.Pipeline
	Queue    *PipelineQueue
}
