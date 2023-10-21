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
	"github.com/google/uuid"
)

var (
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
)

// Initialize the main scheduler
func MainSchedulerInit() {
	mainScheduler = NewScheduler()
}

// Schedule an event in the main scheduler
func MainSchedulerSchedule(e *Event) error {
	return mainScheduler.Schedule(e)
}

// Cancel an event in the main scheduler
func MainSchedulerCancel(uuid uuid.UUID) {
	mainScheduler.Cancel(uuid)
}

// Cancel all events in the main scheduler
func MainSchedulerCancelAll() {
	mainScheduler.CancelAll()
}

// Set an event state in the main scheduler
func MainSchedulerSetEventState(uuid uuid.UUID, state EventState) {
	mainScheduler.SetEventState(uuid, state)
}

// Process the events in the main scheduler
func MainSchedulerProcess() {
	mainScheduler.Process(mainSchedulerProcess)
}
