package scheduler

import (
	"errors"
	"flag"
	"io"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/engine/registry"
	"github.com/owasp-amass/engine/sessions"
	"github.com/owasp-amass/engine/types"
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
	l         *log.Logger
	r         *registry.Registry
	ss        *sessions.Manager
)

type TestEvent struct {
	Message string
}

func setup() {
	l = log.New(io.Discard, "", log.Lmicroseconds)
	r = registry.NewRegistry(l)
	ss = sessions.NewManager(l)

	exitWhenEmpty := flag.Bool("exitWhenEmpty", true, "Exit when the queue is empty")
	checkEvent := flag.Bool("checkEvent", true, "Print event details when processing")
	executeAction := flag.Bool("executeAction", true, "Execute the types.Event action when processing")
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
}

func TestNewScheduler(t *testing.T) {
	setupOnce.Do(setup)

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}
}

func TestSchedule001(t *testing.T) {
	var err error

	setupOnce.Do(setup)
	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := types.Event{
		Name: "Test event",
		Data: TestEvent{
			Message: testMsg,
		},
	}

	if err = s.Schedule(&e); err != nil {
		t.Errorf(err.Error())
	} else if len(s.events) != 1 {
		t.Errorf(errMsgEventScheduleFailed)
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
func TestSchedule002(t *testing.T) {
	var err error

	setupOnce.Do(setup)
	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := types.Event{
		UUID: uuid.New(),
		Name: "Test event (TestSchedule002)",
		Data: TestEvent{
			Message: testMsg,
		},
	}

	if err = s.Schedule(&e); err != nil {
		t.Errorf(err.Error())
	} else if len(s.events) != 1 {
		t.Errorf(errMsgEventScheduleFailed)
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
// - State
func TestSchedule003(t *testing.T) {
	var err error
	setupOnce.Do(setup)

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := types.Event{
		UUID:  uuid.New(),
		Name:  "Test event (TestSchedule003)",
		State: types.EventStateDone,
		Data: TestEvent{
			Message: testMsg,
		},
	}

	if err = s.Schedule(&e); err != nil {
		t.Errorf(err.Error())
	} else if len(s.events) != 1 {
		t.Errorf(errMsgEventScheduleFailed)
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
// - State
// - DependOn
func TestSchedule004(t *testing.T) {
	var err error
	setupOnce.Do(setup)

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := types.Event{
		UUID:     uuid.New(),
		Name:     "Test event (TestSchedule004)",
		State:    types.EventStateDone,
		DependOn: []uuid.UUID{uuid.New()},
		Data: TestEvent{
			Message: testMsg,
		},
	}

	if err = s.Schedule(&e); err != nil {
		t.Errorf(err.Error())
	} else if len(s.events) != 1 {
		t.Errorf(errMsgEventScheduleFailed)
	}
}

// Test Schedule to add an Event in Queue and:
// - UUID
// - State
// - DependOn
// - Timestamp
func TestSchedule005(t *testing.T) {
	var err error
	setupOnce.Do(setup)

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := types.Event{
		UUID:      uuid.New(),
		Name:      "Test event (TestSchedule005)",
		State:     types.EventStateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
		Data: TestEvent{
			Message: testMsg,
		},
	}

	if err = s.Schedule(&e); err != nil {
		t.Errorf(err.Error())
	} else if len(s.events) != 1 {
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
	var err error
	setupOnce.Do(setup)

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := &types.Event{
		UUID:      uuid.New(),
		Name:      "Test event (TestSchedule006)",
		State:     types.EventStateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
		Action: func(e *types.Event) error {
			_, ok := e.Data.(TestEvent) // Type assertion
			if ok {
				return nil
			}
			SetEventState(e, types.EventStateError)
			return errors.New("Error: Type assertion failed")
		},
		Data: TestEvent{
			Message: testMsg,
		},
	}

	if err = s.Schedule(e); err != nil {
		t.Errorf(err.Error())
	} else if len(s.events) != 1 {
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
	var err error
	setupOnce.Do(setup)

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := &types.Event{
		UUID:      uuid.New(),
		Name:      "Test event (TestSchedule007)",
		State:     types.EventStateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Type: types.EventTypeCustom,
	}

	if err = s.Schedule(e); err != nil {
		t.Errorf(err.Error())
	} else if len(s.events) != 1 {
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
	var err error
	setupOnce.Do(setup)

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := &types.Event{
		UUID:      uuid.New(),
		Name:      "Test event (TestSchedule008)",
		State:     types.EventStateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Type:     types.EventTypeCustom,
		Priority: 1,
	}

	if err = s.Schedule(e); err != nil {
		t.Errorf(err.Error())
	} else if len(s.events) != 1 {
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
	var err error
	setupOnce.Do(setup)

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := &types.Event{
		UUID:      uuid.New(),
		Name:      "Test event (TestSchedule009)",
		State:     types.EventStateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Type:        types.EventTypeCustom,
		Priority:    1,
		RepeatEvery: 1,
	}

	if err = s.Schedule(e); err != nil {
		t.Errorf(err.Error())
	} else if len(s.events) != 1 {
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
	var err error
	setupOnce.Do(setup)

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := &types.Event{
		UUID:      uuid.New(),
		Name:      "Test event (TestSchedule010) Random UUID as dependency",
		State:     types.EventStateDone,
		DependOn:  []uuid.UUID{uuid.New()},
		Timestamp: time.Now(),
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Type:        types.EventTypeCustom,
		Priority:    1,
		RepeatEvery: 1,
		RepeatTimes: 1,
	}

	if err = s.Schedule(e); err != nil {
		t.Errorf(err.Error())
	} else if len(s.events) != 1 {
		t.Errorf(errMsgEventScheduleFailed)
	}
}

// Test Schedule to add an Event in Queue and:
// Ensure there are multiple layers of dependencies
func TestSchedule011(t *testing.T) {
	var err error
	setupOnce.Do(setup)

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e0 := &types.Event{Name: "Test event 0 (TestSchedule011)"}
	if err = s.Schedule(e0); err != nil {
		t.Errorf(err.Error())
	}

	e1 := &types.Event{
		Name:     "Test event 1 (TestSchedule011)",
		DependOn: []uuid.UUID{e0.UUID},
	}

	if err = s.Schedule(e1); err != nil {
		t.Errorf(err.Error())
	}

	e2 := &types.Event{
		Name:     "Test event 2 (TestSchedule011)",
		DependOn: []uuid.UUID{e0.UUID},
	}

	if err = s.Schedule(e2); err != nil {
		t.Errorf(err.Error())
	}

	e3 := &types.Event{
		Name:  "Test event 3 (TestSchedule011)",
		State: types.EventStateDone,
		// list of events that must be completed before this event can be processed
		DependOn:  []uuid.UUID{e1.UUID, e2.UUID},
		Timestamp: time.Now(),
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Type:        types.EventTypeCustom,
		Priority:    1,
		RepeatEvery: 1,
		RepeatTimes: 1,
	}

	if err = s.Schedule(e3); err != nil {
		t.Errorf(err.Error())
	} else if len(s.events) < 3 {
		t.Errorf(errMsgEventScheduleFailed)
	}

	s.Process(config)
}

// Test with empty Queue
func TestProcess000(t *testing.T) {
	setupOnce.Do(setup)

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}
	// ... schedule types.Events ...
	s.Process(config)
}

// Test with Event in Queue
func TestProcess001(t *testing.T) {
	setupOnce.Do(setup)

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	// ... schedule types.Events ...
	e := &types.Event{
		Name: "Test event (TestProcess001)",
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
	}
	_ = s.Schedule(e)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
func TestProcess002(t *testing.T) {
	setupOnce.Do(setup)

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := &types.Event{
		Name: "Test event (TestProcess002)",
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
	}
	_ = s.Schedule(e)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
// - Timestamp
func TestProcess003(t *testing.T) {
	setupOnce.Do(setup)

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := &types.Event{
		Name: "Test event (TestProcess003)",
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Timestamp: time.Now(),
	}
	_ = s.Schedule(e)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
// - Timestamp
// - DependOn
func TestProcess004(t *testing.T) {
	setupOnce.Do(setup)

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e0 := &types.Event{
		Name: "Test event 0 (TestProcess004)",
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
	}
	_ = s.Schedule(e0)
	e1 := &types.Event{
		Name: "Test event 1 (TestProcess004)",
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Timestamp: time.Now(),
		DependOn:  []uuid.UUID{e0.UUID},
	}
	_ = s.Schedule(e1)
	s.Process(config)
}

// Test with Event in Queue and:
// - Action
// - Timestamp
// - DependOn
// - State
func TestProcess005(t *testing.T) {
	setupOnce.Do(setup)

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e0 := &types.Event{
		Name:  "Test event 0 (TestProcess005)",
		State: types.EventStateDone,
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
	}
	_ = s.Schedule(e0)
	e1 := &types.Event{
		Name: "Test event 1 (TestProcess005)",
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Timestamp: time.Now(),
		DependOn:  []uuid.UUID{e0.UUID},
	}
	_ = s.Schedule(e1)
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

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e0 := &types.Event{
		Name: "Test event 0 (TestProcess006)",
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
	}
	_ = s.Schedule(e0)
	e1 := &types.Event{
		Name: "Test event 1 (TestProcess006)",
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Timestamp: time.Now(),
		DependOn:  []uuid.UUID{e0.UUID},
		State:     types.EventStateDone,
		Type:      types.EventTypeCustom,
	}
	_ = s.Schedule(e1)
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

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := &types.Event{
		Name: "Test event (TestProcess007) Random UUID as dependency",
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Timestamp: time.Now(),
		DependOn:  []uuid.UUID{uuid.New()},
		State:     types.EventStateDone,
		Type:      types.EventTypeCustom,
		Priority:  1,
	}
	_ = s.Schedule(e)
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

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := &types.Event{
		Name: "Test event (TestProcess008) Random UUID as dependency",
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		DependOn:    []uuid.UUID{uuid.New()},
		State:       types.EventStateDone,
		Type:        types.EventTypeCustom,
		Priority:    1,
		RepeatEvery: 1,
	}
	_ = s.Schedule(e)
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

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := &types.Event{
		Name: "Test event (TestProcess009) Random UUID as dependency",
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Timestamp:   time.Now(),
		DependOn:    []uuid.UUID{uuid.New()},
		State:       types.EventStateDone,
		Type:        types.EventTypeCustom,
		Priority:    1,
		RepeatEvery: 1,
		RepeatTimes: 1,
	}
	_ = s.Schedule(e)
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

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := &types.Event{
		UUID: uuid.New(),
		Name: "Test event (TestProcess010) Random UUID as dependency",
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Timestamp:   time.Now(),
		DependOn:    []uuid.UUID{uuid.New()},
		State:       types.EventStateDone,
		Type:        types.EventTypeCustom,
		Priority:    1,
		RepeatEvery: 1,
		RepeatTimes: 1,
	}
	_ = s.Schedule(e)
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

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := &types.Event{
		UUID: uuid.New(),
		Name: "Test event (TestProcess011) Random UUID as dependency",
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Timestamp:   time.Now(),
		DependOn:    []uuid.UUID{uuid.New()},
		State:       types.EventStateDone,
		Type:        types.EventTypeCustom,
		Priority:    30,
		RepeatEvery: 1,
		RepeatTimes: 1,
	}
	_ = s.Schedule(e)
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

	s := NewScheduler(l, r, ss)
	if s == nil {
		t.Errorf(errMsgSchedulerFailedToInit)
	}

	e := &types.Event{
		UUID: uuid.New(),
		Name: "Test event (TestProcess012) Random UUID as dependency",
		Action: func(e *types.Event) error {
			SetEventState(e, types.EventStateDone)
			return nil
		},
		Data: TestEvent{
			Message: testMsg,
		},
		Timestamp:   time.Now(),
		DependOn:    []uuid.UUID{uuid.New()},
		State:       types.EventStateDone,
		Type:        types.EventTypeCustom,
		Priority:    20,
		RepeatEvery: 1,
		RepeatTimes: 3,
	}
	_ = s.Schedule(e)
	s.Process(config)
}
