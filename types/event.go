package types

import (
	"time"

	"github.com/google/uuid"
)

// Event types (are used to query the Registry adn identify the action to be executed)
type EventType int

const (
	// SystemType is used to identify system events
	EventTypeSystem EventType = iota
	// EventTypeLog is used to log a message to the log file
	EventTypeLog
	// EventTypeCustom is used to execute a custom function
	EventTypeCustom
	// AssetType is used to identify asset events
	EventTypeAsset
	// UnknownType is used to identify unknown events (or all events)
	EventTypeUnknown
	// Add more event types here:
	// ...
)

var (
	// Event types names (used to query the Registry)
	EventTypeNames = map[EventType]string{
		EventTypeSystem:  "System",
		EventTypeLog:     "Log",
		EventTypeCustom:  "Custom",
		EventTypeAsset:   "Asset",
		EventTypeUnknown: "Unknown",
		// Add more event types here:
		// ...
	}

	MaxEventTypes = len(EventTypeNames)
)

// Event states (are used to control the event flow)
type EventState int

const (
	EventStateDefault EventState = iota // Event is in default state
	// (normally used when the event is created)
	EventStateProcessable // Event is processable (all dependencies are met)
	EventStateWaiting     // Event is waiting (some dependencies are not met)
	EventStateDone        // Event is done (already processed)
	EventStateInProcess   // Event is in process (being processed)
	EventStateCancelled   // Event is cancelled (not processed)
	EventStateError       // Event is in error (not processed)
)

// Event is the struct that represents an event
// This struct it's kind of the "currency of exchange" between the scheduler
// and the functions that create and process the events
type Event struct {
	UUID      uuid.UUID           /* Event UUID */
	SessionID uuid.UUID           /* Session UUID */
	Name      string              /* Event name */
	Timestamp time.Time           /* Event timestamp */
	Type      EventType           /* Event type */
	State     EventState          /* Event state (processable, waiting, done, in process) */
	DependOn  []uuid.UUID         /* Events this event "depends on" */
	Action    func(e Event) error /* Event handler function (action) (normally populated by querying the
	-                                Registry)
	-                              */
	Priority    int /* Event priority (normally populated by querying the Registry) */
	RepeatEvery int /* Event repeat every X milliseconds
	-                  0 means repeat immediately
	-                  n means repeat after n milliseconds (n > 0)
	-                  Event won't be repeated if RepeatTimes is 0
	-                */
	RepeatTimes int /* Event repeat times (normally populated by querying the Registry)
	-                  -1 means repeat forever
	-                   0 means don't repeat
	-                   n means repeat n times
	-                 */
	Data interface{} /* This field can hold any data type (normally populated by the function
	-                   that creates the event, and used by the function that processes the
	-                   event)
	-                 */
	Timeout time.Time   /* Timeout timer (used to cancel the event if it's not processed in time) */
	Sched   interface{} /* Pointer to the scheduler that created the event */
	Session interface{} /* Pointer to the session that created the event */
}

// StatsResponse is the struct that represents the response to the Stats request
type SystemStatsResponse struct {
	TotalWorkItemsReceived    int
	TotalWorkItemsDone        int
	TotalWorkItemsCancelled   int
	TotalWorkItemsProcess     int
	TotalWorkItemsError       int
	TotalWorkItemsWaiting     int
	TotalWorkItemsProcessable int
	TotalWorkItemsSystem      int
}

type SessionStatsResponse struct {
	SessionWorkItemsInProcess   int
	SessionWorkItemsWaiting     int
	SessionWorkItemsProcessable int
}
