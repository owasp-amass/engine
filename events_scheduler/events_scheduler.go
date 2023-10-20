package events_scheduler

import (
	"fmt"
	"sync"
	"time"

	"github.com/caffix/queue"
	"github.com/google/uuid"
)

/*
 * Events Scheduler public API
 * This API is used to schedule and process events
 *
 * NewScheduler() *Scheduler    - Creates a new Scheduler instance and returns it
 * Schedule(e *Event) error     - Schedules an event (if there are no errors), returns an error otherwise
 * Cancel(uuid uuid.UUID) error - Cancels a scheduled event (by UUID) if it exists and there are no errors
 *  						      Returns an error otherwise
 * Process(config ProcessConfig)- Processes the events in the queue using the configuration provided
 *  						      via the ProcessConfig struct
 */

// Event types (are used to query the Registry adn identify the action to be executed)
type EventType int

const (
	// EventTypeSay is used to print a message to the console
	EventTypeSay EventType = iota
	// EventTypeLog is used to log a message to the log file
	EventTypeLog
	// Add more event types here:
)

// Event states (are used to control the event flow)
type EventState int

const (
	StateDefault EventState = iota // Event is in default state
	// (normally used when the event is created)
	StateProcessable // Event is processable (all dependencies are met)
	StateWaiting     // Event is waiting (some dependencies are not met)
	StateDone        // Event is done (already processed)
	StateInProcess   // Event is in process (being processed)
	StateCancelled   // Event is cancelled (not processed)
	StateError       // Event is in error (not processed)
)

// Global variables
var (
	// zeroUUID is used to indicate that an event has no dependencies
	zeroUUID = uuid.UUID{}
)

// Event is the struct that represents an event
// This struct it's kind of the "currency of exchange" between the scheduler
// and the functions that create and process the events
type Event struct {
	UUID      uuid.UUID           /* Event UUID */
	Session   uuid.UUID           /* Session UUID */
	Name      string              /* Event name */
	Timestamp time.Time           /* Event timestamp */
	Type      EventType           /* Event type */
	State     EventState          /* Event state (processable, waiting, done, in process) */
	DependOn  []uuid.UUID         /* Events this event "depends on" */
	Action    func(e Event) error /* Event handler function (action) (normally populated by querying the
	-                                Registry)
	-                              */
	Priority    int /* Event priority (normally populated by querying the Registry) */
	RepeatEvery int /* Event repeat every X centiseconds (normally populated by querying
	-			       the Registry)
	-                */
	RepeatTimes int         /* Event repeat times (normally populated by querying the Registry) */
	Data        interface{} /* This field can hold any data type (normally populated by the function
	-                          that creates the event, and used by the function that processes the
	-                          event)
	-                        */
}

// Scheduler is the struct that represents a scheduler
// We have 2 types of schedulers:
//   - Main scheduler, used to schedule and process events, it's the central scheduler and it's
//     allocated on the heap (it's a singleton) and it's initialized by calling
//     the MainSchedulerInit() function.
//   - Sub schedulers, used to schedule and process events, they are allocated on the stack and
//     they are initialized by calling the NewScheduler() function.
type Scheduler struct {
	q      queue.Queue          // Events Queue (Queue to store events)
	mutex  sync.Mutex           // Mutex to protect the queue when fetching the next event
	events map[uuid.UUID]*Event // Map to quickly look up events by UUID
}

// ProcessConfig is the struct that represents the configuration used to process the events
type ProcessConfig struct {
	ExitWhenEmpty bool
	CheckEvent    bool
	ExecuteAction bool
	ReturnIfFound bool
	DebugInfo     bool
}

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

var (
	mainScheduler        *Scheduler
	mainSchedulerProcess = ProcessConfig{
		ExitWhenEmpty: false,
		CheckEvent:    true,
		ExecuteAction: true,
		ReturnIfFound: false,
		DebugInfo:     false,
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

// NewScheduler creates a new Scheduler instance
// Use it to initialize the Scheduler
func NewScheduler() *Scheduler {
	// Initialize the zero UUID (used to indicate that an event has no dependencies)
	zeroUUID, _ = uuid.Parse("00000000-0000-0000-0000-000000000000")
	// Return the scheduler
	return &Scheduler{
		q:      queue.NewQueue(),
		events: make(map[uuid.UUID]*Event),
	}
}

// Schedule schedules an event (public method)
// Use it to add your events to the scheduler
func (s *Scheduler) Schedule(e *Event) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// If the event has no UUID, assign one
	if e.UUID == zeroUUID {
		e.UUID = uuid.New() // Assign a UUID to the event
	}

	// Assign a timestamp to the event which
	// indicate when the event was created
	e.Timestamp = time.Now()

	// Set the event state to waiting
	e.State = StateWaiting
	for _, dependUUID := range e.DependOn {
		// If any dependent event is not done, mark the event as not processable
		if event, exists := s.events[dependUUID]; !exists || event.State != StateDone {
			e.State = StateProcessable
			break
		}
	}

	// If the event has no Session, assign one
	//if e.Session == zeroUUID {
	// Query the Session Handler to get the default session
	//}
	// Using the session, query the Session Handler and the Registry to get the priority, repeat every and repeat times
	// TODO: Implement this

	// If the event has no timestamp, assign one
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now() // Assign a timestamp to the event
	}

	// If the event has no priority, assign one
	if e.Priority <= 0 {
		e.Priority = 1 // Assign a priority to the event
	}

	// If the event has no EventType, assign one
	if e.Type == 0 {
		e.Type = EventTypeSay // Assign a type to the event
	}

	// There is only one special negative value for RepeatTimes (-1)
	if e.RepeatTimes < -1 {
		e.RepeatTimes = -1
	}

	// There are no valid negative values for RepeatEvery
	if e.RepeatEvery < 0 {
		e.RepeatEvery = 0
	}

	// If the event has no Action, assign one
	if e.Action == nil {
		// Query the Registry to get the action (using the EventType)
		e.Action = func(e Event) error {
			s.SetEventState(e.UUID, StateDone)
			return nil
		}
	}

	// Schedule the event
	err := schedule(s, e)

	return err
}

// schedule schedules an event (private method)
func schedule(s *Scheduler, e *Event) error {
	/*
	 * Perform a deep copy of the event (so that it won't be invalidated
	 * when the original event is modified or destructed)
	 */
	eCopy := Event{
		UUID:        e.UUID,
		Session:     e.Session,
		Name:        e.Name,
		Timestamp:   e.Timestamp,
		Type:        e.Type,
		State:       e.State,
		DependOn:    e.DependOn,
		Action:      e.Action,
		Data:        e.Data,
		Priority:    e.Priority,
		RepeatEvery: e.RepeatEvery,
		RepeatTimes: e.RepeatTimes,
	}

	// Store the event in the map
	delete(s.events, e.UUID) // Remove the event from the map (if it exists)
	s.events[e.UUID] = &eCopy

	// Append the event to the queue with the correct priority
	s.q.AppendPriority(eCopy, eCopy.Priority)

	return nil
}

// Cancel cancels an event
// Use it to cancel an event
func (s *Scheduler) Cancel(uuid uuid.UUID) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if event, exists := s.events[uuid]; exists {
		event.State = StateCancelled
		// Cancel all the events that depend on this event
		removeEventAndDeps(s, uuid)
	}
}

// CancelAll cancels all events
// Use it to cancel all events
func (s *Scheduler) CancelAll() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, event := range s.events {
		event.State = StateCancelled
	}
}

// GetEvent returns an event by reference
// Use it to get an event by UUID (to transform its state for example)
// (private method)
func getEvent(s *Scheduler, uuid uuid.UUID) *Event {
	if event, exists := s.events[uuid]; exists {
		return event
	}
	return nil
}

// SetEventState sets the state of an event in the scheduler queue
// Use it to set the state of an event by UUID
// (public method)
func (s *Scheduler) SetEventState(uuid uuid.UUID, state EventState) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	setEventState(s, uuid, state)
}

// setEventState sets the state of an event in the scheduler queue
// (private method)
func setEventState(s *Scheduler, uuid uuid.UUID, state EventState) {
	if event, exists := s.events[uuid]; exists {
		event.State = state
	}
}

// removeEventAndDeps removes an event and the events that depends on it from the scheduler queue
func removeEventAndDeps(s *Scheduler, uuid uuid.UUID) {
	// Check for all the events that depend on this event
	for _, event := range s.events {
		for _, dependUUID := range event.DependOn {
			if dependUUID == uuid {
				// If the event depends on the event we are removing, set its state to cancelled
				// and remove it from the events map
				event.State = StateCancelled
				delete(s.events, event.UUID)
			}
		}
	}
	// Remove the event from the events map
	delete(s.events, uuid)
}

// Process processes the events in a queue
// it's parametric, so it requires a ProcessConfig struct
// Use it to start the scheduler
func (s *Scheduler) Process(config ProcessConfig) {
	// Events processing loop
	for {
		s.mutex.Lock()

		// If the queue is empty, wait for a second and continue
		if s.q.Len() == 0 || s.q.Empty() {
			if config.ExitWhenEmpty {
				s.mutex.Unlock()
				return
			}
			s.mutex.Unlock()
			time.Sleep(1 * time.Second)
			continue
		}

		// Get the next event from the queue (and remove it from the queue)
		// s.q.Next() should return the event with the highest priority in the queue
		// (if there are more events with the same priority, it should return the first one)
		// Note: s.q.Next() returns an interface{}, so we need to cast it to an Event
		var event Event
		ok := true
		element, ok := s.q.Next() // workaround to get all events
		event = element.(Event)
		if ok {
			// If the event in being processed then continue to the next event
			if event.State == StateInProcess {
				s.mutex.Unlock()
				continue
			}

			// If the event is cancelled, remove it from the events map
			// and continue to the next event
			if event.State == StateCancelled || event.State == StateError {
				if event.State == StateError {
					// TODO: Transform these prints into logs (when the Logger is implemented)
					fmt.Println("The element presented an error: ", event)
				}
				removeEventAndDeps(s, event.UUID)
				s.mutex.Unlock()
				continue
			}
			// If the event is done, check if it needs to be repeated
			if event.State == StateDone {
				// If the event is repeatable, schedule it again
				if event.RepeatEvery == 0 && event.RepeatTimes > 0 {
					// If the event is repeatable, schedule it again
					event.State = StateProcessable
					event.RepeatTimes--
					delete(s.events, event.UUID)
					err := schedule(s, &event)
					if err != nil {
						// TODO: Transform these prints into logs (when the Logger is implemented)
						fmt.Println(err)
					}
				} else if event.RepeatEvery > 0 && event.RepeatTimes > 0 {
					// If the event is repeatable, schedule it again
					// Note: this if statement controls both the repeat every and repeat times
					//       If we need an event to be repeated for ever, we can set RepeatTimes to -1
					event.State = StateProcessable
					event.Timestamp = time.Now()
					event.RepeatTimes--
					delete(s.events, event.UUID)
					err := schedule(s, &event)
					if err != nil {
						// TODO: Transform these prints into logs (when the Logger is implemented)
						fmt.Println(err)
					}
				} else if event.RepeatEvery >= 0 && event.RepeatTimes == -1 {
					// If the event is repeatable, schedule it again (for ever)
					event.State = StateProcessable
					delete(s.events, event.UUID)
					err := schedule(s, &event)
					if err != nil {
						// TODO: Transform these prints into logs (when the Logger is implemented)
						fmt.Println(err)
					}
				} else {
					// If the event is not repeatable, remove it from the events map
					delete(s.events, event.UUID)
				}
				s.mutex.Unlock()
				continue
			}
		}
		if !ok {
			// If the event is not ok, remove it from the events map
			// and continue to the next event
			delete(s.events, event.UUID)
			if config.DebugInfo {
				// TODO: Transform these prints into logs (when the Logger is implemented)
				fmt.Println("The element presented a problem: ", event)
			}
			s.mutex.Unlock()
			continue
		}

		// Check if all dependencies are met
		canProcess := true
		for _, dependUUID := range event.DependOn {
			if depEvent, exists := s.events[dependUUID]; exists && depEvent.State != StateDone {
				if config.DebugInfo {
					// TODO: Transform these prints into logs (when the Logger is implemented)
					fmt.Printf("Event %s can't be processed because it depends on event %s, which is not done yet\n", event.UUID, dependUUID)
					fmt.Printf("Event %s is in state %d\n", dependUUID, depEvent.State)
				}
				if dependUUID != event.UUID && dependUUID != zeroUUID {
					canProcess = false
				}
				break
			}
		}
		if canProcess &&
			time.Now().After(event.Timestamp.Add(time.Duration(time.Duration(event.RepeatEvery)*time.Millisecond))) {

			// If it can be processed, process it
			if config.CheckEvent {
				// TODO: Transform these prints into logs (when the Logger is implemented)
				fmt.Printf("Processing event: %s (UUID: %s)\n", event.Name, event.UUID)
				fmt.Println("Event body: ", event)
			}

			// Set the event state to in process
			event.State = StateInProcess

			// Execute the action
			errCh := make(chan error)
			if config.ExecuteAction && event.Action != nil {
				// TODO: add an actions counter and when we reach max wait

				// Schedule the event again with its new state
				err := schedule(s, &event)
				if err == nil {
					// Execute the action in a goroutine
					go func(e Event) {
						err := e.Action(e)
						if err != nil {
							errCh <- err
						}
					}(event)
				}
			}
			if config.ReturnIfFound {
				s.mutex.Unlock()
				return
			}
		} else {
			// If it can't be processed, append it back to the queue
			delete(s.events, event.UUID)
			err := schedule(s, &event)
			if err != nil {
				// TODO: Transform these prints into logs (when the Logger is implemented)
				fmt.Println(err)
			}
		}

		s.mutex.Unlock()
	}
}
