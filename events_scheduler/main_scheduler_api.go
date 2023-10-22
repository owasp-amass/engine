package events_scheduler

/*
 * Main Scheduler public API
 * This API is used to schedule and process events on the main scheduler (as per Amass requirements)
 *
 * MainSchedulerInit()                   - Initializes the main scheduler
 * MainSchedulerSchedule(e *Event) error - Schedules an event (if there are no errors), returns an
 *                                         error otherwise
 * MainSchedulerCancel(uuid uuid.UUID)   - Cancels a scheduled event (by UUID) if it exists and there
 *                                         are no errors
 * MainSchedulerCancelAll()              - Cancels all scheduled events
 * MainSchedulerProcess()                - Processes the events in the queue
 */

import (
	"fmt"

	"github.com/google/uuid"
)

const (
	errMainSchedulerNotInitialized = "main scheduler is not initialized"
	errEventIsNil                  = "event is nil"
)

var (
	runType              = 0 // 0 = production, 1 = test
	mainScheduler        *Scheduler
	mainSchedulerProcess = ProcessConfig{
		ExitWhenEmpty:        false,
		CheckEvent:           true,
		ExecuteAction:        true,
		ReturnIfFound:        false,
		DebugInfo:            false,
		ActionTimeout:        30,
		MaxConcurrentActions: 10,
	}
	mainSchedulerProcessTest = ProcessConfig{
		ExitWhenEmpty:        true,
		CheckEvent:           true,
		ExecuteAction:        true,
		ReturnIfFound:        false,
		DebugInfo:            false,
		ActionTimeout:        30,
		MaxConcurrentActions: 10,
	}
)

// Initialize the main scheduler
func MainSchedulerInit() error {
	if mainScheduler == nil {
		mainScheduler = NewScheduler()
	}
	if mainScheduler == nil {
		return fmt.Errorf(errMainSchedulerNotInitialized)
	}
	return nil
}

// Schedule an event in the main scheduler
func MainSchedulerSchedule(e *Event) error {
	if e == nil {
		return fmt.Errorf(errEventIsNil)
	}
	if mainScheduler == nil {
		return fmt.Errorf(errMainSchedulerNotInitialized)
	}
	return mainScheduler.Schedule(e)
}

// Cancel an event in the main scheduler
func MainSchedulerCancel(uuid uuid.UUID) error {
	if mainScheduler == nil {
		return fmt.Errorf(errMainSchedulerNotInitialized)
	}
	mainScheduler.Cancel(uuid)
	return nil
}

// Cancel all events in the main scheduler
func MainSchedulerCancelAll() error {
	if mainScheduler == nil {
		return fmt.Errorf(errMainSchedulerNotInitialized)
	}
	mainScheduler.CancelAll()
	return nil
}

// Shutdown the main scheduler
func MainSchedulerShutdown() error {
	if mainScheduler == nil {
		return fmt.Errorf(errMainSchedulerNotInitialized)
	}
	MainSchedulerCancelAll()
	mainScheduler = nil
	return nil
}

// Set an event state in the main scheduler
func MainSchedulerSetEventState(uuid uuid.UUID, state EventState) error {
	if mainScheduler == nil {
		return fmt.Errorf(errMainSchedulerNotInitialized)
	}
	mainScheduler.SetEventState(uuid, state)
	return nil
}

// Process the events in the main scheduler
func MainSchedulerProcess() error {
	if mainScheduler == nil {
		return fmt.Errorf(errMainSchedulerNotInitialized)
	}
	if runType == 0 {
		mainScheduler.Process(mainSchedulerProcess)
	} else {
		mainScheduler.Process(mainSchedulerProcessTest)
	}
	return nil
}
