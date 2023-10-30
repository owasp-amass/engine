package scheduler

import (
	"sync"

	"github.com/owasp-amass/engine/registry"
	"github.com/owasp-amass/engine/types"
)

func processEvent(e types.Event, errCh chan error) {
	sc := e.Sched.(*Scheduler)
	switch e.Type {
	case types.EventTypeAsset:
		handlers, ok := sc.r.GetHandlers(types.EventTypeAsset, "")
		if ok != nil {
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
