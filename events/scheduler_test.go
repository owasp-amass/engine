package events

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Global constants
const (
	testMsg                     = "Hello world"
	errMsgEventScheduleFailed   = "Event scheduling failed"
	errMsgSchedulerFailedToInit = "Scheduler failed to initialize"
)

// Global vars
var (
	config    ProcessConfig
	setupOnce sync.Once
	testLog   *log.Logger
)

type TestEvent struct {
	Message string
}

func setup() {
	// Setup test logger
	testLog = log.New(os.Stdout, "Test: ", log.Ldate|log.Ltime|log.Lshortfile)

	exitWhenEmpty := flag.Bool("exitWhenEmpty", true, "Exit when the queue is empty")
	checkEvent := flag.Bool("checkEvent", true, "Print event details when processing")
	executeAction := flag.Bool("executeAction", true, "Execute the event action when processing")
	returnIfFound := flag.Bool("returnIfFound", false, "Return if an event is found")

	flag.Parse()

	config = ProcessConfig{
		ExitWhenEmpty:        *exitWhenEmpty,
		CheckEvent:           *checkEvent,
		ExecuteAction:        *executeAction,
		ReturnIfFound:        *returnIfFound,
		DebugLevel:           0,
		ActionTimeout:        60,
		MaxConcurrentActions: 10,
	}
	fmt.Println("Tests config:")
	fmt.Printf("%+v\n", config)
}

func TestNewScheduler(t *testing.T) {
	setupOnce.Do(setup)

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}
}

func TestSchedule001(t *testing.T) {
	fmt.Println("\nTestSchedule001")

	var err error

	setupOnce.Do(setup)

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := Event{
		Name: "Test event",
		Data: TestEvent{
			Message: testMsg,
		},
	}
	err = s.Schedule(&e)
	if err != nil {
		t.Errorf(err.Error())
	}

	if err == nil && len(s.events) != 1 {
		t.Errorf(errMsgEventScheduleFailed)
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
func TestSchedule002(t *testing.T) {
	fmt.Println("\nTestSchedule002")

	var err error

	setupOnce.Do(setup)

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := Event{
		UUID: uuid.New(),
		Name: "Test event (TestSchedule002)",
		Data: TestEvent{
			Message: testMsg,
		},
	}
	err = s.Schedule(&e)
	if err != nil {
		t.Errorf(err.Error())
	}

	if err == nil && len(s.events) != 1 {
		t.Errorf(errMsgEventScheduleFailed)
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
// - State
func TestSchedule003(t *testing.T) {
	fmt.Println("\nTestSchedule003")

	setupOnce.Do(setup)

	var err error

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := Event{
		UUID:  uuid.New(),
		Name:  "Test event (TestSchedule003)",
		State: StateDone,
		Data: TestEvent{
			Message: testMsg,
		},
	}
	err = s.Schedule(&e)
	if err != nil {
		t.Errorf(err.Error())
	}

	if err == nil && len(s.events) != 1 {
		t.Errorf(errMsgEventScheduleFailed)
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
// - State
// - DependOn
func TestSchedule004(t *testing.T) {
	fmt.Println("\nTestSchedule004")

	setupOnce.Do(setup)

	var err error

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := Event{
		UUID:     uuid.New(),
		Name:     "Test event (TestSchedule004)",
		State:    StateDone,
		DependOn: []uuid.UUID{uuid.New()},
		Data: TestEvent{
			Message: testMsg,
		},
	}
	err = s.Schedule(&e)
	if err != nil {
		t.Errorf(err.Error())
	}

	if err == nil && len(s.events) != 1 {
		t.Errorf(errMsgEventScheduleFailed)
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
// - State
// - DependOn
// - Timestamp
func TestSchedule005(t *testing.T) {
	fmt.Println("\nTestSchedule005")

	setupOnce.Do(setup)

	var err error

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := Event{
		UUID:      uuid.New(),
		Name:      "Test event (TestSchedule005)",
		State:     StateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
		Data: TestEvent{
			Message: testMsg,
		},
	}
	err = s.Schedule(&e)
	if err != nil {
		t.Errorf(err.Error())
	}

	if err == nil && len(s.events) != 1 {
		t.Errorf(errMsgEventScheduleFailed)
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
// - State
// - DependOn
// - Timestamp
// - Action
func TestSchedule006(t *testing.T) {
	fmt.Println("\nTestSchedule006")

	setupOnce.Do(setup)

	var err error

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

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
			Message: testMsg,
		},
	}
	err = s.Schedule(&e)
	if err != nil {
		t.Errorf(err.Error())
	}

	if err == nil && len(s.events) != 1 {
		t.Errorf(errMsgEventScheduleFailed)
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
	fmt.Println("\nTestSchedule007")

	setupOnce.Do(setup)

	var err error

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

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
			Message: testMsg,
		},
		Type: EventTypeCustom,
	}
	err = s.Schedule(&e)
	if err != nil {
		t.Errorf(err.Error())
	}

	if err == nil && len(s.events) != 1 {
		t.Errorf(errMsgEventScheduleFailed)
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

	fmt.Println("\nTestSchedule008")

	setupOnce.Do(setup)

	var err error

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

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
			Message: testMsg,
		},
		Type:     EventTypeCustom,
		Priority: 1,
	}
	err = s.Schedule(&e)
	if err != nil {
		t.Errorf(err.Error())
	}

	if err == nil && len(s.events) != 1 {
		t.Errorf(errMsgEventScheduleFailed)
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

	fmt.Println("\nTestSchedule009")

	setupOnce.Do(setup)

	var err error

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

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
			Message: testMsg,
		},
		Type:        EventTypeCustom,
		Priority:    1,
		RepeatEvery: 1,
	}
	err = s.Schedule(&e)
	if err != nil {
		t.Errorf(err.Error())
	}

	if err == nil && len(s.events) != 1 {
		t.Errorf(errMsgEventScheduleFailed)
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

	fmt.Println("\nTestSchedule010")

	setupOnce.Do(setup)

	var err error

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

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
			Message: testMsg,
		},
		Type:        EventTypeCustom,
		Priority:    1,
		RepeatEvery: 1,
		RepeatTimes: 1,
	}
	err = s.Schedule(&e)
	if err != nil {
		t.Errorf(err.Error())
	}

	if err == nil && len(s.events) != 1 {
		t.Errorf(errMsgEventScheduleFailed)
	}
}

// Test Schedule to add an Event in Queue and:
// Ensure there are multiple layers of dependencies
func TestSchedule011(t *testing.T) {

	fmt.Println("\nTestSchedule011")

	setupOnce.Do(setup)

	var err error

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e0 := Event{
		Name: "Test event 0 (TestSchedule011)",
	}
	err = s.Schedule(&e0)
	if err != nil {
		t.Errorf(err.Error())
	}

	e1 := Event{
		Name:     "Test event 1 (TestSchedule011)",
		DependOn: []uuid.UUID{e0.UUID},
	}
	err = s.Schedule(&e1)
	if err != nil {
		t.Errorf(err.Error())
	}

	e2 := Event{
		Name:     "Test event 2 (TestSchedule011)",
		DependOn: []uuid.UUID{e0.UUID},
	}
	err = s.Schedule(&e2)
	if err != nil {
		t.Errorf(err.Error())
	}

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
			Message: testMsg,
		},
		Type:        EventTypeCustom,
		Priority:    1,
		RepeatEvery: 1,
		RepeatTimes: 1,
	}
	err = s.Schedule(&e3)
	if err != nil {
		t.Errorf(err.Error())
	}

	if err == nil && len(s.events) < 3 {
		t.Errorf(errMsgEventScheduleFailed)
	}

	s.Process(config)

}

// Test with empty Queue
func TestProcess000(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestProcess000")

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	// ... schedule events ...

	s.Process(config)

}

// Test with Event in Queue
func TestProcess001(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestProcess001")

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	// ... schedule events ...

	e := Event{
		Name: "Test event (TestProcess001)",
		Action: func(e Event) error {
			SetEventState(&e, StateDone)
			return nil
		},
	}
	_ = s.Schedule(&e)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
func TestProcess002(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestProcess002")

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := Event{
		Name: "Test event (TestProcess002)",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
	}
	_ = s.Schedule(&e)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
// - Timestamp
func TestProcess003(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestProcess003")

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := Event{
		Name: "Test event (TestProcess003)",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Timestamp: time.Now(),
	}
	_ = s.Schedule(&e)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
// - Timestamp
// - DependOn
func TestProcess004(t *testing.T) {

	setupOnce.Do(setup)

	fmt.Println("\nTestProcess004")

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e0 := Event{
		Name: "Test event 0 (TestProcess004)",
		Action: func(e Event) error {
			SetEventState(&e, StateDone)
			return nil
		},
	}
	_ = s.Schedule(&e0)
	e1 := Event{
		Name: "Test event 1 (TestProcess004)",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Timestamp: time.Now(),
		DependOn:  []uuid.UUID{e0.UUID},
	}
	_ = s.Schedule(&e1)
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

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e0 := Event{
		Name:  "Test event 0 (TestProcess005)",
		State: StateDone,
		Action: func(e Event) error {
			SetEventState(&e, StateDone)
			return nil
		},
	}
	_ = s.Schedule(&e0)
	e1 := Event{
		Name: "Test event 1 (TestProcess005)",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Timestamp: time.Now(),
		DependOn:  []uuid.UUID{e0.UUID},
	}
	_ = s.Schedule(&e1)
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

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e0 := Event{
		Name: "Test event 0 (TestProcess006)",
		Action: func(e Event) error {
			SetEventState(&e, StateDone)
			return nil
		},
	}
	_ = s.Schedule(&e0)
	e1 := Event{
		Name: "Test event 1 (TestProcess006)",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Timestamp: time.Now(),
		DependOn:  []uuid.UUID{e0.UUID},
		State:     StateDone,
		Type:      EventTypeCustom,
	}
	_ = s.Schedule(&e1)
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

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := Event{
		Name: "Test event (TestProcess007) Random UUID as dependency",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Timestamp: time.Now(),
		DependOn:  []uuid.UUID{uuid.New()},
		State:     StateDone,
		Type:      EventTypeCustom,
		Priority:  1,
	}
	_ = s.Schedule(&e)
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

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := Event{
		Name: "Test event (TestProcess008) Random UUID as dependency",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		DependOn:    []uuid.UUID{uuid.New()},
		State:       StateDone,
		Type:        EventTypeCustom,
		Priority:    1,
		RepeatEvery: 1,
	}
	_ = s.Schedule(&e)
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

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := Event{
		Name: "Test event (TestProcess009) Random UUID as dependency",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Timestamp:   time.Now(),
		DependOn:    []uuid.UUID{uuid.New()},
		State:       StateDone,
		Type:        EventTypeCustom,
		Priority:    1,
		RepeatEvery: 1,
		RepeatTimes: 1,
	}
	_ = s.Schedule(&e)
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

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := Event{
		UUID: uuid.New(),
		Name: "Test event (TestProcess010) Random UUID as dependency",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Timestamp:   time.Now(),
		DependOn:    []uuid.UUID{uuid.New()},
		State:       StateDone,
		Type:        EventTypeCustom,
		Priority:    1,
		RepeatEvery: 1,
		RepeatTimes: 1,
	}
	_ = s.Schedule(&e)
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

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := Event{
		UUID: uuid.New(),
		Name: "Test event (TestProcess011) Random UUID as dependency",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Timestamp:   time.Now(),
		DependOn:    []uuid.UUID{uuid.New()},
		State:       StateDone,
		Type:        EventTypeCustom,
		Priority:    30,
		RepeatEvery: 1,
		RepeatTimes: 1,
	}
	_ = s.Schedule(&e)
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

	s := NewScheduler(testLog)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := Event{
		UUID: uuid.New(),
		Name: "Test event (TestProcess012) Random UUID as dependency",
		Action: func(e Event) error {
			fmt.Println(e.Data.(TestEvent).Message)
			SetEventState(&e, StateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Timestamp:   time.Now(),
		DependOn:    []uuid.UUID{uuid.New()},
		State:       StateDone,
		Type:        EventTypeCustom,
		Priority:    20,
		RepeatEvery: 1,
		RepeatTimes: 3,
	}
	_ = s.Schedule(&e)
	s.Process(config)
}
