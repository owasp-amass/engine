// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"fmt"

	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	multierror "github.com/hashicorp/go-multierror"
	et "github.com/owasp-amass/engine/types"
)

func (r *Registry) NewEventDataElement(e *et.Event) *EventDataElement {
	return &EventDataElement{Event: e}
}

func (ede *EventDataElement) Clone() pipeline.Data {
	return ede
}

func (r *Registry) BuildPipelines() error {
	r.Lock()
	defer r.Unlock()

	for k := range r.handlers {
		p, err := r.buildAssetPipeline(string(k))
		if err != nil {
			return err
		}
		r.pipelines[k] = p
	}
	return nil
}

func (r *Registry) buildAssetPipeline(atype string) (*AssetPipeline, error) {
	var stages []pipeline.Stage

	for priority := 1; priority <= 9; priority++ {
		handlers, found := r.handlers[atype][priority]
		if !found || len(handlers) == 0 {
			continue
		}

		if len(handlers) == 1 {
			if h := handlers[0]; h != nil {
				stages = append(stages, pipeline.FIFO(h.Name, handlerTask(h)))
			}
		} else {
			var tasks []pipeline.Task

			for _, handler := range handlers {
				if h := handlerTask(handler); h != nil {
					tasks = append(tasks, h)
				}
			}

			id := fmt.Sprintf("%s - Priority: %d", atype, priority)
			stages = append(stages, pipeline.Parallel(id, tasks...))
		}
	}

	ap := &AssetPipeline{
		Pipeline: pipeline.NewPipeline(stages...),
		Queue:    &PipelineQueue{queue.NewQueue()},
	}

	go func(p *AssetPipeline) {
		if err := p.Pipeline.ExecuteBuffered(context.TODO(), p.Queue, makeSink(), 50); err != nil {
			r.Log.Printf("Pipeline %s terminated: %v", atype, err)
		}
	}(ap)
	return ap, nil
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

func makeSink() pipeline.SinkFunc {
	return pipeline.SinkFunc(func(ctx context.Context, data pipeline.Data) error {
		ede, ok := data.(*EventDataElement)
		if !ok {
			return errors.New("pipeline sink failed to extract the EventDataElement")
		}

		ede.Queue.Append(ede)
		return nil
	})
}

func handlerTask(h *Handler) pipeline.TaskFunc {
	if h == nil || h.Handler == nil {
		return nil
	}

	r := h
	return pipeline.TaskFunc(func(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
		if data == nil {
			return nil, fmt.Errorf("%s pipeline task received a nil data element", h.Name)
		}

		ede, ok := data.(*EventDataElement)
		if !ok || ede == nil {
			return nil, fmt.Errorf("%s pipeline task failed to extract the EventDataElement", h.Name)
		}

		select {
		case <-ctx.Done():
			ede.Queue.Append(ede)
			return nil, nil
		default:
		}

		if err := r.Handler(ede.Event); err != nil {
			ede.Error = multierror.Append(ede.Error, err)
		}

		return data, nil
	})
}
