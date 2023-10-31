package scheduler

import (
	"strings"
	"sync"

	"github.com/owasp-amass/engine/registry"
	"github.com/owasp-amass/engine/sessions"
	"github.com/owasp-amass/engine/types"
)

func processEvent(e types.Event, errCh chan error) {
	sc := e.Sched.(*Scheduler)
	switch e.Type {
	case types.EventTypeAsset:
		// Get the asset data from the event
		EventData := e.Data.(types.AssetData)
		assetType := EventData.OAMType

		// Get the transformers associated with this event type
		ss := e.Session.(*sessions.Session)
		cfg := ss.Cfg

		// Get the transformers associated with this ss.Cfg
		// Look up the transformation for the asset type
		transformation, ok := cfg.Transformations[string(assetType)]
		if !ok {
			// No transformations configured for this asset type
			// So set the event as done and return
			SetEventState(&e, types.EventStateDone)
			return
		}
		tName := string(transformation.To)
		tName = strings.ToLower(strings.TrimSpace(tName))

		// Get the handlers associated with this event type
		handlers, err := sc.r.GetHandlers(assetType, tName)
		if err != nil {
			return // Or handle the error appropriately
		}

		var wg sync.WaitGroup
		errCh := make(chan error, len(handlers)) // Buffered channel to collect errors

		for _, handler := range handlers {
			wg.Add(1)
			eventCopy := e // Make a shallow copy of the event for each goroutine
			go func(handler registry.Handler, e types.Event) {
				defer wg.Done() // Ensure the wait group counter is decremented

				if err := handler.Handler(&e); err != nil {
					errCh <- err // Send the error to the channel
				}
			}(handler, eventCopy)
		}

		wg.Wait()    // Wait for all handler goroutines to finish
		close(errCh) // Close the channel after all goroutines have finished

		// Collect errors from the channel
		var errors []error
		var numErrs int = 0
		for err := range errCh {
			if err != nil {
				errors = append(errors, err)
				numErrs++
			}
		}

		// Handle the collected errors
		for _, err := range errors {
			sc.logger.Println("Handler error:", err)
			// Additional error handling here
		}

		// All handlers have completed at this point
		if numErrs > 0 {
			SetEventState(&e, types.EventStateError)
		} else {
			SetEventState(&e, types.EventStateDone)
		}

	case types.EventTypeSystem, types.EventTypeCustom:
		if e.Action != nil {
			err := e.Action(e)
			if err != nil {
				errCh <- err
			}
		}

	case types.EventTypeLog:
		// Assuming you have a logger setup, for demonstration:
		sc.logger.Printf("LOG EVENT: %s\n", e.Name)
		SetEventState(&e, types.EventStateDone)

	default:
		// Handle any other unexpected event types if needed
	}
}
