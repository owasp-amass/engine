package events_scheduler

import (
	"fmt"
	"sync"
	"time"

	"github.com/caffix/queue"
	"github.com/google/uuid"
)

type EventType int

const (
	EventTypeSay EventType = iota
	EventTypeLog
)

type EventState int

const (
	StateDefault EventState = iota // Event is in default state
	// (normally used when the event is created)
	StateProcessable // Event is processable (all dependencies are met)
	StateWaiting     // Event is waiting (some dependencies are not met)
	StateDone        // Event is done (already processed)
	StateInProcess   // Event is in process (being processed)
)

var (
	zeroUUID = uuid.UUID{}
)

// Event is the struct that represents an event
// This struct it's kind of the "currency of exchange" between the scheduler
// and the functions that create and process the events
type Event struct {
	UUID        uuid.UUID           // Event UUID
	Session     uuid.UUID           // Session UUID
	Name        string              // Event name
	Timestamp   time.Time           // Event timestamp
	Type        EventType           // Event type
	State       EventState          // Event state (processable, waiting, done, in process)
	DependOn    []uuid.UUID         // Events this event depends on
	Action      func(e Event) error // Event handler function (action) (normally populated by querying the Registry)
	Priority    int                 // Event priority (normally populated by querying the Registry)
	RepeatEvery int                 // Event repeat every (normally populated by querying the Registry)
	RepeatTimes int                 // Event repeat times (normally populated by querying the Registry)
	Data        interface{}         /* This field can hold any data type (normally populated by the function
	   that creates the event, and used by the function that processes the event)
	*/
}

type Scheduler struct {
	q      queue.Queue          // Events Queue (Queue to store events)
	mutex  sync.Mutex           // Mutex to protect the queue when fetching the next event
	events map[uuid.UUID]*Event // Map to quickly look up events by UUID
}

type ProcessConfig struct {
	ExitWhenEmpty bool
	CheckEvent    bool
	ExecuteAction bool
	ReturnIfFound bool
	DebugInfo     bool
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

// Schedule schedules an event
// Use it to add your events to the scheduler
func (s *Scheduler) Schedule(e *Event) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// If the event has no UUID, assign one
	if e.UUID == zeroUUID {
		e.UUID = uuid.New() // Assign a UUID to the event
	}

	// If the event has no timestamp, assign one
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now() // Assign a timestamp to the event
	}

	// If the event has no priority, assign one
	if e.Priority == 0 {
		e.Priority = 1 // Assign a priority to the event
	}

	// If the event has no EventType, assign one
	if e.Type == 0 {
		e.Type = EventTypeSay // Assign a type to the event
	}

	// If the event has no State, assign one
	if e.State == StateDefault {
		e.State = StateWaiting
		for _, dependUUID := range e.DependOn {
			// If any dependent event is not done, mark the event as not processable
			if event, exists := s.events[dependUUID]; !exists || event.State != StateDone {
				e.State = StateProcessable
				break
			}
		}
	}

	// If the event has no Action, assign one
	if e.Action == nil {
		// Query the Registry to get the action (using the EventType)
	}

	// If the event has no Session, assign one
	if e.Session == zeroUUID {
		// Query the Session Handler to get the default session
	}
	// Using the session, query the Session Handler and the Registry to get the priority, repeat every and repeat times
	// TODO: Implement this

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

	s.events[e.UUID] = &eCopy                 // Store the event in the map
	s.q.AppendPriority(eCopy, eCopy.Priority) // Append the event to the queue with the correct priority
}

// Cancel cancels an event
// Use it to cancel an event
func (s *Scheduler) Cancel(uuid uuid.UUID) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if event, exists := s.events[uuid]; exists {
		event.State = StateDone
	}
}

// GetNextEvent returns the next event in the queue
// Use it to get the next event in the queue
func (s *Scheduler) GetNextEvent() *Event {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.q.Len() == 0 || s.q.Empty() {
		return nil
	}

	var event Event
	ok := true
	s.q.Process(func(e interface{}) {
		if event, ok = e.(Event); ok {
			if event.State == StateDone {
				ok = false
			}
		}
	})
	if !ok {
		if event.State == StateDone {
			// If the event is done, then it was already processed
			// Let's make sure to remove it from the events map
			// RemoveDoneEventFromDependOn(s, &event)
			delete(s.events, event.UUID)
		} else {
			// Log this error: ("the element at index %d presented a problem", i)
			fmt.Println("The element presented a problem")
		}
		return nil
	}

	// Check if all dependencies are met
	canProcess := true
	for _, dependUUID := range event.DependOn {
		if depEvent, exists := s.events[dependUUID]; !exists || depEvent.State != StateDone {
			if dependUUID != event.UUID && dependUUID != zeroUUID {
				canProcess = false
			}
			break
		}
	}
	if canProcess && time.Now().After(event.Timestamp) {
		// If it can be processed, process it
		event.State = StateInProcess
	} else {
		// If it can't be processed, append it back to the queue
		s.q.AppendPriority(event, event.Priority)
		return nil
	}

	return &event
}

// GetEvent returns an event
// Use it to get an event by UUID
func (s *Scheduler) GetEvent(uuid uuid.UUID) *Event {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if event, exists := s.events[uuid]; exists {
		return event
	}
	return nil
}

// Remove done event (passed as UUID) from DependOn lists on all events
// Use it to remove a specific done event from the DependOn lists on all events
/* Not needed at the moment, given the event queue returns all copies of the event
   I have implemented a workaround to have it dynamically updated
func RemoveDoneEventFromDependOn(s *Scheduler, e *Event) {
	for _, event := range s.events {
		for i, dependUUID := range event.DependOn {
			if dependUUID == e.UUID {
				if i == 0 {
					event.DependOn = event.DependOn[1:]
				} else {
					event.DependOn = append(event.DependOn[:i-1], event.DependOn[i+1:]...)
				}
			}
		}
	}
	delete(s.events, e.UUID)
}
*/

// Process processes the events in a queue
// it's parametric, so it requires a ProcessConfig struct
// Use it to start the scheduler
func (s *Scheduler) Process(config ProcessConfig) {
	for {
		s.mutex.Lock()

		if s.q.Len() == 0 || s.q.Empty() {
			if config.ExitWhenEmpty {
				s.mutex.Unlock()
				return
			}
			s.mutex.Unlock()
			time.Sleep(1 * time.Second)
			continue
		}

		var event Event
		ok := true
		/*  This is the my original code, however,
		    s.q.Process in caffix/queue seems to be skipping
			some events, so I have implemented a workaround below
			s.q.Process(func(e interface{}) {
				if event, ok = e.(Event); ok {
					if config.DebugInfo {
						fmt.Println("Got event: ", event)
					}
					if event.State == StateDone {
						ok = false
					}
				}
			})
		*/
		element, ok := s.q.Next() // workaround to get all events
		event = element.(Event)
		if ok {
			if config.DebugInfo {
				fmt.Println("Got event: ", event)
			}
			if event.State == StateDone {
				ok = false
			}
		}
		if !ok {
			if event.State == StateDone {
				// If the event is done, then it was already processed
				// Let's make sure to remove it from the events map
				// RemoveDoneEventFromDependOn(s, &event)
				delete(s.events, event.UUID)
			} else {
				// Log this error: ("the element at index %d presented a problem", i)
				fmt.Println("The element presented a problem")
			}
			s.mutex.Unlock()
			continue
		}

		// Check if all dependencies are met
		canProcess := true
		for _, dependUUID := range event.DependOn {
			if depEvent, exists := s.events[dependUUID]; exists && depEvent.State != StateDone {
				if config.DebugInfo {
					fmt.Printf("Event %s can't be processed because it depends on event %s, which is not done yet\n", event.UUID, dependUUID)
					fmt.Printf("Event %s is in state %d\n", dependUUID, depEvent.State)

				}
				if dependUUID != event.UUID && dependUUID != zeroUUID {
					canProcess = false
				}
				break
			}
		}
		if canProcess && time.Now().After(event.Timestamp) {
			// If it can be processed, process it
			if config.CheckEvent {
				fmt.Printf("Processing event: %s (UUID: %s)\n", event.Name, event.UUID)
			}
			event.State = StateInProcess
			// Execute the action
			errCh := make(chan error)
			if config.ExecuteAction && event.Action != nil {
				go func(e Event) {
					err := e.Action(e)
					if err != nil {
						errCh <- err
					}
				}(event)
			}
			// Wait for the action to finish
			/* select {
				case err := <-errCh:
					// handle error
				default:
					// no error, continue
			} */
			event.State = StateDone
			// If the event is repeatable, schedule it again
			if event.RepeatEvery > 0 && event.RepeatTimes > 0 {
				event.Timestamp = event.Timestamp.Add(time.Duration(event.RepeatEvery) * time.Second)
				event.RepeatTimes--
				s.Schedule(&event)
			} else {
				// If the event is not repeatable, remove it from the events map
				//RemoveDoneEventFromDependOn(s, &event)
				delete(s.events, event.UUID)
			}
			if config.ReturnIfFound {
				s.mutex.Unlock()
				return
			}
		} else {
			// If it can't be processed, append it back to the queue
			s.q.AppendPriority(event, event.Priority)
		}

		s.mutex.Unlock()
	}
}
