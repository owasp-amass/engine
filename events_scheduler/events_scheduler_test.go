package events_scheduler

import (
	"flag"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Global vars
var (
	config    ProcessConfig
	setupOnce sync.Once
)

type TestEvent struct {
	Message string
}

func setup() {
	exitWhenEmpty := flag.Bool("exitWhenEmpty", true, "Exit when the queue is empty")
	checkEvent := flag.Bool("checkEvent", true, "Print event details when processing")
	executeAction := flag.Bool("executeAction", true, "Execute the event action when processing")
	returnIfFound := flag.Bool("returnIfFound", false, "Return if an event is found")
	debugInfo := flag.Bool("DebugInfo", false, "Print debug info")

	flag.Parse()

	config = ProcessConfig{
		ExitWhenEmpty:        *exitWhenEmpty,
		CheckEvent:           *checkEvent,
		ExecuteAction:        *executeAction,
		ReturnIfFound:        *returnIfFound,
		DebugInfo:            *debugInfo,
		ActionTimeout:        60,
		MaxConcurrentActions: 10,
	}
	fmt.Println("Tests config:")
	fmt.Printf("%+v\n", config)

	/*
		config = ProcessConfig{
			ExitWhenEmpty: true,
			CheckEvent:    true,
			ExecuteAction: true,
			ReturnIfFound: true,
			DebugInfo:     true,
		}*/
}

func TestNewScheduler(t *testing.T) {
	setupOnce.Do(setup)

	s := NewScheduler()
	if s == nil {
		t.Errorf("NewScheduler() returned nil")
	}
}

func TestSchedule001(t *testing.T) {
	setupOnce.Do(setup)

	s := NewScheduler()
	e := Event{
		Name: "Test event",
		Data: TestEvent{
			Message: "Hello world",
		},
	}
	s.Schedule(&e)
	if len(s.events) != 1 {
		t.Errorf("Schedule() did not add the event to the events map")
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
func TestSchedule002(t *testing.T) {
	setupOnce.Do(setup)

	s := NewScheduler()
	e := Event{
		UUID: uuid.New(),
		Name: "Test event (TestSchedule002)",
		Data: TestEvent{
			Message: "Hello world",
		},
	}
	s.Schedule(&e)
	if len(s.events) != 1 {
		t.Errorf("Schedule() did not add the event to the events map")
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
// - State
func TestSchedule003(t *testing.T) {
	setupOnce.Do(setup)

	s := NewScheduler()
	e := Event{
		UUID:  uuid.New(),
		Name:  "Test event (TestSchedule003)",
		State: StateDone,
		Data: TestEvent{
			Message: "Hello world",
		},
	}
	s.Schedule(&e)
	if len(s.events) != 1 {
		t.Errorf("Schedule() did not add the event to the events map")
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
// - State
// - DependOn
func TestSchedule004(t *testing.T) {
	setupOnce.Do(setup)

	s := NewScheduler()
	e := Event{
		UUID:     uuid.New(),
		Name:     "Test event (TestSchedule004)",
		State:    StateDone,
		DependOn: []uuid.UUID{uuid.New()},
		Data: TestEvent{
			Message: "Hello world",
		},
	}
	s.Schedule(&e)
	if len(s.events) != 1 {
		t.Errorf("Schedule() did not add the event to the events map")
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
// - State
// - DependOn
// - Timestamp
func TestSchedule005(t *testing.T) {
	setupOnce.Do(setup)

	s := NewScheduler()
	e := Event{
		UUID:      uuid.New(),
		Name:      "Test event (TestSchedule005)",
		State:     StateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
		Data: TestEvent{
			Message: "Hello world",
		},
	}
	s.Schedule(&e)
	if len(s.events) != 1 {
		t.Errorf("Schedule() did not add the event to the events map")
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
// - State
// - DependOn
// - Timestamp
// - Action
func TestSchedule006(t *testing.T) {
	setupOnce.Do(setup)

	s := NewScheduler()
	e := Event{
		UUID:      uuid.New(),
		Name:      "Test event (TestSchedule006)",
		State:     StateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
		Action: func(e Event) error {
			data, ok := e.Data.(TestEvent) // Type assertion
			if ok {
				fmt.Println(data)
				return nil
			}
			SetEventState(&e, StateError)
			return fmt.Errorf("Error: Type assertion failed")
		},
		Data: TestEvent{
			Message: "Hello world",
		},
	}
	s.Schedule(&e)
	if len(s.events) != 1 {
		t.Errorf("Schedule() did not add the event to the events map")
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
// - State
// - DependOn
// - Timestamp
// - Action
// - Type
func TestSchedule007(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestSchedule007")

	s := NewScheduler()
	e := Event{
		UUID:      uuid.New(),
		Name:      "Test event (TestSchedule007)",
		State:     StateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: "Hello world",
		},
		Type: EventTypeSay,
	}
	s.Schedule(&e)
	if len(s.events) != 1 {
		t.Errorf("Schedule() did not add the event to the events map")
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
// - State
// - DependOn
// - Timestamp
// - Action
// - Type
// - Priority
func TestSchedule008(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestSchedule008")

	s := NewScheduler()
	e := Event{
		UUID:      uuid.New(),
		Name:      "Test event (TestSchedule008)",
		State:     StateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: "Hello world",
		},
		Type:     EventTypeSay,
		Priority: 1,
	}
	s.Schedule(&e)
	if len(s.events) != 1 {
		t.Errorf("Schedule() did not add the event to the events map")
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
// - State
// - DependOn
// - Timestamp
// - Action
// - Type
// - Priority
// - RepeatEvery
func TestSchedule009(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestSchedule009")

	s := NewScheduler()
	e := Event{
		UUID:      uuid.New(),
		Name:      "Test event (TestSchedule009)",
		State:     StateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: "Hello world",
		},
		Type:        EventTypeSay,
		Priority:    1,
		RepeatEvery: 1,
	}
	s.Schedule(&e)
	if len(s.events) != 1 {
		t.Errorf("Schedule() did not add the event to the events map")
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
// - Action
// - Timestamp
// - DependOn (with random UUID)
// - State
// - Type
// - Priority
// - RepeatEvery
// - RepeatTimes
func TestSchedule010(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestSchedule010")

	s := NewScheduler()
	e := Event{
		UUID:      uuid.New(),
		Name:      "Test event (TestSchedule010) Random UUID as dependency",
		State:     StateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: "Hello world",
		},
		Type:        EventTypeSay,
		Priority:    1,
		RepeatEvery: 1,
		RepeatTimes: 1,
	}
	s.Schedule(&e)
	if len(s.events) != 1 {
		t.Errorf("Schedule() did not add the event to the events map")
	}
}

// Test Schedule to add an Event in Queue and:
// Ensure there are multiple layers of dependencies
func TestSchedule011(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestSchedule011")

	s := NewScheduler()

	e0 := Event{
		Name: "Test event 0 (TestSchedule011)",
	}
	s.Schedule(&e0)

	e1 := Event{
		Name:     "Test event 1 (TestSchedule011)",
		DependOn: []uuid.UUID{e0.UUID},
	}
	s.Schedule(&e1)

	e2 := Event{
		Name:     "Test event 2 (TestSchedule011)",
		DependOn: []uuid.UUID{e0.UUID},
	}
	s.Schedule(&e2)

	e3 := Event{
		Name:  "Test event 3 (TestSchedule011)",
		State: StateDone,
		// list of events that must be completed before this event can be processed
		DependOn:  []uuid.UUID{e1.UUID, e2.UUID},
		Timestamp: time.Now(),
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: "Hello world",
		},
		Type:        EventTypeSay,
		Priority:    1,
		RepeatEvery: 1,
		RepeatTimes: 1,
	}
	s.Schedule(&e3)

	if len(s.events) < 3 {
		t.Errorf("Schedule() did not add the event to the events map")
	}

	s.Process(config)

}

// Test with empty Queue
func TestProcess000(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestProcess000")

	s := NewScheduler()

	// ... schedule events ...

	s.Process(config)

}

// Test with Event in Queue
func TestProcess001(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestProcess001")

	s := NewScheduler()

	// ... schedule events ...

	e := Event{
		Name: "Test event (TestProcess001)",
		Action: func(e Event) error {
			SetEventState(&e, StateDone)
			return nil
		},
	}
	s.Schedule(&e)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
func TestProcess002(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestProcess002")

	s := NewScheduler()
	e := Event{
		Name: "Test event (TestProcess002)",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: "Hello world",
		},
	}
	s.Schedule(&e)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
// - Timestamp
func TestProcess003(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestProcess003")

	s := NewScheduler()
	e := Event{
		Name: "Test event (TestProcess003)",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: "Hello world",
		},
		Timestamp: time.Now(),
	}
	s.Schedule(&e)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
// - Timestamp
// - DependOn
func TestProcess004(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestProcess004")

	s := NewScheduler()
	e0 := Event{
		Name: "Test event 0 (TestProcess004)",
		Action: func(e Event) error {
			SetEventState(&e, StateDone)
			return nil
		},
	}
	s.Schedule(&e0)
	e1 := Event{
		Name: "Test event 1 (TestProcess004)",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: "Hello world",
		},
		Timestamp: time.Now(),
		DependOn:  []uuid.UUID{e0.UUID},
	}
	s.Schedule(&e1)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
// - Timestamp
// - DependOn
// - State
func TestProcess005(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestProcess005")

	s := NewScheduler()
	e0 := Event{
		Name:  "Test event 0 (TestProcess005)",
		State: StateDone,
		Action: func(e Event) error {
			SetEventState(&e, StateDone)
			return nil
		},
	}
	s.Schedule(&e0)
	e1 := Event{
		Name: "Test event 1 (TestProcess005)",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: "Hello world",
		},
		Timestamp: time.Now(),
		DependOn:  []uuid.UUID{e0.UUID},
	}
	s.Schedule(&e1)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
// - Timestamp
// - DependOn
// - State
// - Type
func TestProcess006(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestProcess006")

	s := NewScheduler()
	e0 := Event{
		Name: "Test event 0 (TestProcess006)",
		Action: func(e Event) error {
			SetEventState(&e, StateDone)
			return nil
		},
	}
	s.Schedule(&e0)
	e1 := Event{
		Name: "Test event 1 (TestProcess006)",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: "Hello world",
		},
		Timestamp: time.Now(),
		DependOn:  []uuid.UUID{e0.UUID},
		State:     StateDone,
		Type:      EventTypeSay,
	}
	s.Schedule(&e1)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
// - Timestamp
// - DependOn
// - State
// - Type
// - Priority
func TestProcess007(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestProcess007")

	s := NewScheduler()
	e := Event{
		Name: "Test event (TestProcess007) Random UUID as dependency",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: "Hello world",
		},
		Timestamp: time.Now(),
		DependOn:  []uuid.UUID{uuid.New()},
		State:     StateDone,
		Type:      EventTypeSay,
		Priority:  1,
	}
	s.Schedule(&e)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
// - Timestamp
// - DependOn
// - State
// - Type
// - Priority
// - RepeatEvery
func TestProcess008(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestProcess008")

	s := NewScheduler()
	e := Event{
		Name: "Test event (TestProcess008) Random UUID as dependency",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: "Hello world",
		},
		DependOn:    []uuid.UUID{uuid.New()},
		State:       StateDone,
		Type:        EventTypeSay,
		Priority:    1,
		RepeatEvery: 1,
	}
	s.Schedule(&e)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
// - Timestamp
// - DependOn
// - State
// - Type
// - Priority
// - RepeatEvery
// - RepeatTimes
func TestProcess009(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestProcess009")

	s := NewScheduler()
	e := Event{
		Name: "Test event (TestProcess009) Random UUID as dependency",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: "Hello world",
		},
		Timestamp:   time.Now(),
		DependOn:    []uuid.UUID{uuid.New()},
		State:       StateDone,
		Type:        EventTypeSay,
		Priority:    1,
		RepeatEvery: 1,
		RepeatTimes: 1,
	}
	s.Schedule(&e)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
// - Timestamp
// - DependOn
// - State
// - Type
// - Priority
// - RepeatEvery
// - RepeatTimes
// - UUID
func TestProcess010(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestProcess010")

	s := NewScheduler()
	e := Event{
		UUID: uuid.New(),
		Name: "Test event (TestProcess010) Random UUID as dependency",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: "Hello world",
		},
		Timestamp:   time.Now(),
		DependOn:    []uuid.UUID{uuid.New()},
		State:       StateDone,
		Type:        EventTypeSay,
		Priority:    1,
		RepeatEvery: 1,
		RepeatTimes: 1,
	}
	s.Schedule(&e)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
// - Timestamp
// - DependOn
// - State
// - Type
// - Priority
// - RepeatEvery
// - RepeatTimes
// - UUID
// - Mutex
func TestProcess011(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestProcess011")

	s := NewScheduler()
	e := Event{
		UUID: uuid.New(),
		Name: "Test event (TestProcess011) Random UUID as dependency",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: "Hello world",
		},
		Timestamp:   time.Now(),
		DependOn:    []uuid.UUID{uuid.New()},
		State:       StateDone,
		Type:        EventTypeSay,
		Priority:    30,
		RepeatEvery: 1,
		RepeatTimes: 1,
	}
	s.Schedule(&e)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
// - Timestamp
// - DependOn
// - State
// - Type
// - Priority
// - RepeatEvery
// - RepeatTimes
// - UUID
// - Mutex
// - Queue
func TestProcess012(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestProcess012")

	s := NewScheduler()
	e := Event{
		UUID: uuid.New(),
		Name: "Test event (TestProcess012) Random UUID as dependency",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: "Hello world",
		},
		Timestamp:   time.Now(),
		DependOn:    []uuid.UUID{uuid.New()},
		State:       StateDone,
		Type:        EventTypeSay,
		Priority:    20,
		RepeatEvery: 1,
		RepeatTimes: 3,
	}
	s.Schedule(&e)
	s.Process(config)
}
