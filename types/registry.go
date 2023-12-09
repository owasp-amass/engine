// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
	"log"

	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	oam "github.com/owasp-amass/open-asset-model"
)

type Plugin interface {
	Start(r Registry) error
	Stop()
}

type Handler struct {
	Name       string
	Priority   int
	EventType  oam.AssetType
	Transforms []string
	Callback   func(*Event) error
}

type AssetPipeline struct {
	Pipeline *pipeline.Pipeline
	Queue    *PipelineQueue
}

type Registry interface {
	Log() *log.Logger
	RegisterHandler(h *Handler) error
	BuildPipelines() error
	GetPipeline(eventType oam.AssetType) (*AssetPipeline, error)
}

type PipelineQueue struct {
	queue.Queue
}

func NewPipelineQueue() *PipelineQueue {
	return &PipelineQueue{queue.NewQueue()}
}

// Next implements the pipeline InputSource interface.
func (pq *PipelineQueue) Next(ctx context.Context) bool {
	if pq.Queue.Len() > 0 {
		return true
	}

	for {
		select {
		case <-ctx.Done():
			return false
		case <-pq.Queue.Signal():
			if pq.Queue.Len() > 0 {
				return true
			}
		}
	}
}

// Data implements the pipeline InputSource interface.
func (pq *PipelineQueue) Data() pipeline.Data {
	if element, ok := pq.Queue.Next(); ok {
		return element.(*EventDataElement)
	}
	return nil
}

// Error implements the pipeline InputSource interface.
func (pq *PipelineQueue) Error() error {
	return nil
}
