// Structures required to create and process events

package events

import (
	"log"
	"sync"

	"github.com/caffix/queue"
	"github.com/google/uuid"
	"github.com/owasp-amass/engine/types"
)

// Global variables
var (
	// zeroUUID is used to indicate that an event has no dependencies
	zeroUUID = uuid.UUID{}
)

type SchedulerState int

const (
	SchedulerStateRunning  SchedulerState = iota // Scheduler is running
	SchedulerStateShutdown                       // Scheduler is stopped
	SchedulerStatePaused                         // Scheduler is paused
)

// Scheduler is the struct that represents a scheduler
// We have 2 types of schedulers:
//   - Main scheduler, used to schedule and process events, it's the central scheduler and it's
//     allocated on the heap (it's a singleton) and it's initialized by calling
//     the MainSchedulerInit() function.
//   - Sub schedulers, used to schedule and process events, they are allocated on the stack and
//     they are initialized by calling the NewScheduler() function.
type Scheduler struct {
	q                     queue.Queue                // Events Queue (Queue to store events)
	mutex                 sync.Mutex                 // Mutex to protect the queue when fetching the next event
	events                map[uuid.UUID]*types.Event // Map to quickly look up events by UUID
	CurrentRunningActions int                        // Number of actions currently running
	state                 SchedulerState             // Scheduler state (running, stopped, paused)
	logger                *log.Logger                // Logger
}

// ProcessConfig is the struct that represents the configuration used to process the events
type ProcessConfig struct {
	ExitWhenEmpty        bool // Return from the Process() function when the queue is empty (instead of waiting for new events)
	CheckEvent           bool // Check if the event is processable (instead of just processing it)
	ExecuteAction        bool // Execute the action (instead of just processing the event), used for debugging purposes
	ReturnIfFound        bool // Return from the Process() function when the event is found (instead of waiting for new events)
	DebugLevel           int  // Print debug info
	ActionTimeout        int  // Action timeout (in milliseconds)
	MaxConcurrentActions int  // Maximum number of concurrent actions allowed
}
