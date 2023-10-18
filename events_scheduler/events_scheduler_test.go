package events_scheduler

import (
	"flag"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Global vars
var (
	config ProcessConfig
)

func TestNewScheduler(t *testing.T) {
	s := NewScheduler()
	if s == nil {
		t.Errorf("NewScheduler() returned nil")
	}
}

func TestSchedule001(t *testing.T) {
	s := NewScheduler()
	e := Event{
		Name: "Test event",
	}
	s.Schedule(&e)
	if len(s.events) != 1 {
		t.Errorf("Schedule() did not add the event to the events map")
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
func TestSchedule002(t *testing.T) {
	s := NewScheduler()
	e := Event{
		UUID: uuid.New(),
		Name: "Test event",
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
	s := NewScheduler()
	e := Event{
		UUID:  uuid.New(),
		Name:  "Test event",
		State: StateDone,
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
	s := NewScheduler()
	e := Event{
		UUID:     uuid.New(),
		Name:     "Test event",
		State:    StateDone,
		DependOn: []uuid.UUID{uuid.New()},
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
	s := NewScheduler()
	e := Event{
		UUID:      uuid.New(),
		Name:      "Test event",
		State:     StateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
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
	s := NewScheduler()
	e := Event{
		UUID:      uuid.New(),
		Name:      "Test event",
		State:     StateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
		Action: func() {
			fmt.Println("Hello world")
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
	s := NewScheduler()
	e := Event{
		UUID:      uuid.New(),
		Name:      "Test event",
		State:     StateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
		Action: func() {
			fmt.Println("Hello world")
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
	s := NewScheduler()
	e := Event{
		UUID:      uuid.New(),
		Name:      "Test event",
		State:     StateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
		Action: func() {
			fmt.Println("Hello world")
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
	s := NewScheduler()
	e := Event{
		UUID:      uuid.New(),
		Name:      "Test event",
		State:     StateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
		Action: func() {
			fmt.Println("Hello world")
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
// - DependOn
// - State
// - Type
// - Priority
// - RepeatEvery
// - RepeatTimes
func TestSchedule010(t *testing.T) {
	s := NewScheduler()
	e := Event{
		UUID:      uuid.New(),
		Name:      "Test event",
		State:     StateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
		Action: func() {
			fmt.Println("Hello world")
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

// Test with empty Queue
func TestProcess000(t *testing.T) {
	exitWhenEmpty := flag.Bool("exitWhenEmpty", true, "Exit when the queue is empty")
	checkEvent := flag.Bool("checkEvent", true, "Print event details when processing")
	executeAction := flag.Bool("executeAction", true, "Execute the event action when processing")
	returnIfFound := flag.Bool("returnIfFound", true, "Return if an event is found")
	debugInfo := flag.Bool("DebugInfo", true, "Print debug info")

	flag.Parse()

	s := NewScheduler()

	// ... schedule events ...

	config = ProcessConfig{
		ExitWhenEmpty: *exitWhenEmpty,
		CheckEvent:    *checkEvent,
		ExecuteAction: *executeAction,
		ReturnIfFound: *returnIfFound,
		DebugInfo:     *debugInfo,
	}
	fmt.Printf("%+v\n", config)

	s.Process(config)

}

// Test with Event in Queue
func TestProcess001(t *testing.T) {

	s := NewScheduler()

	// ... schedule events ...

	e := Event{
		Name: "Test event",
	}
	s.Schedule(&e)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
func TestProcess002(t *testing.T) {
	s := NewScheduler()
	e := Event{
		Name: "Test event",
		Action: func() {
			fmt.Println("Hello world")
		},
	}
	s.Schedule(&e)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
// - Timestamp
func TestProcess003(t *testing.T) {
	s := NewScheduler()
	e := Event{
		Name: "Test event",
		Action: func() {
			fmt.Println("Hello world")
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
	s := NewScheduler()
	e0 := Event{
		Name: "Test event 0",
	}
	s.Schedule(&e0)
	e1 := Event{
		Name: "Test event",
		Action: func() {
			fmt.Println("Hello world")
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
	s := NewScheduler()
	e0 := Event{
		Name:  "Test event 0",
		State: StateDone,
	}
	s.Schedule(&e0)
	e1 := Event{
		Name: "Test event",
		Action: func() {
			fmt.Println("Hello world")
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
	s := NewScheduler()
	e0 := Event{
		Name: "Test event 0",
	}
	s.Schedule(&e0)
	e1 := Event{
		Name: "Test event",
		Action: func() {
			fmt.Println("Hello world")
		},
		Timestamp: time.Now(),
		DependOn:  []uuid.UUID{e0.UUID},
		State:     StateDone,
		Type:      EventTypeSay,
	}
	s.Schedule(&e1)
	s.Process(config)
}

/*
// Test with Event in Queue and:
// - Action
// - Timestamp
// - DependOn
// - State
// - Type
// - Priority
func TestProcess007(t *testing.T) {
	s := NewScheduler()
	e := Event{
		Name: "Test event",
		Action: func() {
			fmt.Println("Hello world")
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
	s := NewScheduler()
	e := Event{
		Name: "Test event",
		Action: func() {
			fmt.Println("Hello world")
		},
		Timestamp:   time.Now(),
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
	s := NewScheduler()
	e := Event{
		Name: "Test event",
		Action: func() {
			fmt.Println("Hello world")
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
	s := NewScheduler()
	e := Event{
		UUID: uuid.New(),
		Name: "Test event",
		Action: func() {
			fmt.Println("Hello world")
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
	s := NewScheduler()
	e := Event{
		UUID: uuid.New(),
		Name: "Test event",
		Action: func() {
			fmt.Println("Hello world")
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
	s := NewScheduler()
	e := Event{
		UUID: uuid.New(),
		Name: "Test event",
		Action: func() {
			fmt.Println("Hello world")
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
*/
