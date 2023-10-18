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

type Event struct {
	UUID        uuid.UUID   // Event UUID
	Session     uuid.UUID   // Session UUID
	Name        string      // Event name
	Timestamp   time.Time   // Event timestamp
	Type        EventType   // Event type
	State       EventState  // Event state (processable, waiting, done, in process)
	DependOn    []uuid.UUID // Events this event depends on
	Action      func()      // Event handler function (action) (normally populated by querying the Registry)
	Priority    int         // Event priority (normally populated by querying the Registry)
	RepeatEvery int         // Event repeat every (normally populated by querying the Registry)
	RepeatTimes int         // Event repeat times (normally populated by querying the Registry)
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

	e.UUID = uuid.New() // Assign a UUID to the event
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
			s.RemoveDoneEventFromDependOn(event.UUID)
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
		s.q.Append(event)
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

// Remove done events from DependOn lists
// Use it to remove done events from the DependOn lists
func (s *Scheduler) RemoveDoneEventsFromDependOn() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, event := range s.events {
		if event.State == StateDone {
			for i, dependUUID := range event.DependOn {
				if depEvent, exists := s.events[dependUUID]; exists && depEvent.State == StateDone {
					event.DependOn = append(event.DependOn[:i], event.DependOn[i+1:]...)
				}
			}
		}
	}
}

// Remove done event (passed as UUID) from DependOn lists on all events
// Use it to remove a specific done event from the DependOn lists on all events
func (s *Scheduler) RemoveDoneEventFromDependOn(uuid uuid.UUID) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if event, exists := s.events[uuid]; exists && event.State == StateDone {
		for _, event := range s.events {
			for i, dependUUID := range event.DependOn {
				if dependUUID == uuid {
					event.DependOn = append(event.DependOn[:i], event.DependOn[i+1:]...)
				}
			}
		}
	}
}

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
		if !ok {
			s.mutex.Unlock()
			if event.State == StateDone {
				// If the event is done, then it was already processed
				// Let's make sure to remove it from the events map
				s.RemoveDoneEventFromDependOn(event.UUID)
				delete(s.events, event.UUID)
			} else {
				// Log this error: ("the element at index %d presented a problem", i)
				fmt.Println("The element presented a problem")
			}
			continue
		}

		// Check if all dependencies are met
		canProcess := true
		for _, dependUUID := range event.DependOn {
			if depEvent, exists := s.events[dependUUID]; !exists || depEvent.State != StateDone {
				if config.DebugInfo {
					fmt.Printf("Event %s can't be processed because it depends on event %s, which is not done yet\n", event.UUID, dependUUID)
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
			if config.ExecuteAction && event.Action != nil {
				event.Action()
			}
			event.State = StateDone
			if config.ReturnIfFound {
				s.mutex.Unlock()
				return
			}
		} else {
			// If it can't be processed, append it back to the queue
			s.q.Append(event)
		}

		s.mutex.Unlock()
	}
}

/*
func main() {
	s := NewScheduler()

	event1 := Event{
		Name:      "Say Hello",
		Timestamp: time.Now().Add(2 * time.Second),
		Type:      EventTypeSay,
		Action: func() {
			fmt.Println("Hello!")
		},
	}

	s.Schedule(event1)

	event2 := Event{
		Name:      "Say Goodbye",
		Timestamp: time.Now().Add(5 * time.Second),
		Type:      EventTypeSay,
		DependOn:  []uuid.UUID{event1.UUID},
		Action: func() {
			fmt.Println("Goodbye!")
		},
	}

	s.Schedule(event2)

	s.Process()
}
*/
