/*
 * Events Scheduler public API
 * This API is used to schedule and process events
 *
 * NewScheduler() *Scheduler    - Creates a new Scheduler instance and returns it
 * Schedule(e *types.Event) error     - Schedules an event (if there are no errors), returns an error otherwise
 * Cancel(uuid uuid.UUID) error - Cancels a scheduled event (by UUID) if it exists and there are no errors
 *  						      Returns an error otherwise
 * Process(config ProcessConfig)- Processes the events in the queue using the configuration provided
 *  						      via the ProcessConfig struct
 */

package scheduler

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/caffix/queue"
	"github.com/google/uuid"
	"github.com/owasp-amass/engine/registry"
	"github.com/owasp-amass/engine/sessions"
	"github.com/owasp-amass/engine/types"
)

// NewScheduler creates a new Scheduler instance
// Use it to initialize the Scheduler
func NewScheduler(l *log.Logger, r *registry.Registry, s *sessions.Manager) *Scheduler {
	// Initialize the zero UUID (used to indicate that an event has no dependencies)
	zeroUUID, _ = uuid.Parse("00000000-0000-0000-0000-000000000000")
	// Initialize the logger
	if l == nil {
		l = log.New(os.Stdout, "", log.LstdFlags)
	}
	// Return the scheduler
	return &Scheduler{
		q:      queue.NewQueue(),
		events: make(map[uuid.UUID]*types.Event),
		logger: l,
		r:      r,
		s:      s,
		stats: schedulerStats{
			TotalEventsReceived:    0,
			TotalEventsDone:        0,
			TotalEventsCancelled:   0,
			TotalEventsInProcess:   0,
			TotalEventsError:       0,
			TotalEventsWaiting:     0,
			TotalEventsProcessable: 0,
			TotalEventsSystem:      0,
		},
	}
}

func setupEvent(e *types.Event) {
	// If the event has no UUID, assign one
	if e.UUID == zeroUUID {
		e.UUID = uuid.New() // Assign a UUID to the event
	}

	// Assign a timestamp to the event which
	// indicate when the event was created
	e.Timestamp = time.Now()

	// There is only one special negative value for RepeatTimes (-1)
	if e.RepeatTimes < -1 {
		e.RepeatTimes = -1
	}

	// There are no valid negative values for RepeatEvery
	if e.RepeatEvery < 0 {
		e.RepeatEvery = 0
	}
}

// Schedule schedules an event (public method)
// Use it to add your events to the scheduler
func (s *Scheduler) Schedule(e *types.Event) error {

	// Check if the scheduler is nil
	if s == nil {
		return fmt.Errorf("the scheduler has not been initialized")
	}

	// Check if the event is nil
	if e == nil {
		return fmt.Errorf("the event is nil")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Setup the event
	setupEvent(e)

	// Set the event state to waiting
	e.State = types.EventStateWaiting
	for _, dependUUID := range e.DependOn {
		// If any dependent event is not done, mark the event as not processable
		if event, exists := s.events[dependUUID]; !exists || event.State != types.EventStateDone {
			e.State = types.EventStateProcessable
			break
		} else {
			if event.Priority <= e.Priority {
				// If the event has a higher priority than the dependent event, decrease the priority of the dependent event to avoid starvation
				e.Priority = event.Priority - 1
			}
		}
	}
	// If the event has no priority, assign one
	if e.Priority <= 0 {
		e.Priority = 1 // Assign a priority to the event
	}

	// If the event has no Session, assign one
	//if e.Session == zeroUUID {
	// Query the Session Handler to get the default session
	//}
	// Using the session, query the Session Handler and the Registry to get the priority, repeat every and repeat times
	// TODO: Implement this
	e.Session = s.s.Get(e.SessionID)

	// Make sure the event has the scheduler reference
	// (this is used to set the event state to cancelled when the scheduler is cancelled)
	e.Sched = s

	// Schedule the event
	err := schedule(s, e)
	if err == nil {
		s.stats.TotalEventsReceived++
	}

	return err
}

// schedule schedules an event (private method)
func schedule(s *Scheduler, e *types.Event) error {
	/*
	 * Perform a deep copy of the event (so that it won't be invalidated
	 * when the original event is modified or destructed)
	 */
	eCopy := types.Event{
		UUID:        e.UUID,
		SessionID:   e.SessionID,
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
		Timeout:     e.Timeout,
		Sched:       s,
	}

	if e.Sched == nil {
		eCopy.Sched = s
	}

	// If the event has no Action, assign one
	if eCopy.Action == nil {
		// Query the Registry to get the action (using the EventType)
		eCopy.Action = func(e types.Event) error {
			SetEventState(&e, types.EventStateDone)
			return nil
		}
	}

	// Store the types.Event in the map
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
		event.State = types.EventStateCancelled
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
		event.State = types.EventStateCancelled
	}
	s.stats.TotalEventsCancelled += len(s.events)
}

// Shutdown cancels all events and stops the scheduler
// Use it to stop the scheduler
func (s *Scheduler) Shutdown() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, event := range s.events {
		event.State = types.EventStateCancelled
	}
	s.stats.TotalEventsCancelled += len(s.events)
	s.state = SchedulerStateShutdown
}

// Get Scheduler statistics
func (s *Scheduler) GetStats(sid uuid.UUID) schedulerStats {
	if sid == zeroUUID || sid == uuid.Nil {
		return s.stats
	}
	sessionStats := schedulerStats{}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Copy scheduler stats in session stats
	sessionStats.TotalEventsReceived = s.stats.TotalEventsReceived
	sessionStats.TotalEventsDone = s.stats.TotalEventsDone
	sessionStats.TotalEventsCancelled = s.stats.TotalEventsCancelled
	sessionStats.TotalEventsInProcess = s.stats.TotalEventsInProcess
	sessionStats.TotalEventsError = s.stats.TotalEventsError
	sessionStats.TotalEventsWaiting = s.stats.TotalEventsWaiting
	sessionStats.TotalEventsProcessable = s.stats.TotalEventsProcessable
	sessionStats.TotalEventsSystem = s.stats.TotalEventsSystem

	for _, event := range s.events {
		if event.SessionID == sid {
			if event.State == types.EventStateInProcess {
				sessionStats.SessionEventsInProcess++
			} else if event.State == types.EventStateProcessable {
				sessionStats.SessionEventsProcessable++
			} else if event.State == types.EventStateWaiting {
				sessionStats.SessionEventsWaiting++
			}
		}
	}
	return sessionStats
}

// GetEvent returns an event by reference
// Use it to get an event by UUID (to transform its state for example)
// (private method)
/*func getEvent(s *Scheduler, uuid uuid.UUID) *types.Event {
	if event, exists := s.events[uuid]; exists {
		return event
	}
	return nil
}*/

// SetEventState sets the state of an event in the scheduler queue
// Use it to set the state of an event by UUID
// (public method)
func (s *Scheduler) SetEventState(uuid uuid.UUID, state types.EventState) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	setEventState(s, uuid, state)
}

func updateSchedulerStats(s *Scheduler, oldState types.EventState, newState types.EventState) {
	if oldState != newState {
		// Update stats
		if newState == types.EventStateCancelled {
			s.stats.TotalEventsCancelled++
		} else if newState == types.EventStateDone {
			s.stats.TotalEventsDone++
		} else if newState == types.EventStateError {
			s.stats.TotalEventsError++
		} else if newState == types.EventStateInProcess {
			s.stats.TotalEventsInProcess++
		} else if newState == types.EventStateProcessable {
			s.stats.TotalEventsProcessable++
		} else if newState == types.EventStateWaiting {
			s.stats.TotalEventsWaiting++
		}
		if oldState == types.EventStateCancelled {
			s.stats.TotalEventsCancelled--
		} else if oldState == types.EventStateDone {
			s.stats.TotalEventsDone--
		} else if oldState == types.EventStateError {
			s.stats.TotalEventsError--
		} else if oldState == types.EventStateInProcess {
			s.stats.TotalEventsInProcess--
		} else if oldState == types.EventStateProcessable {
			s.stats.TotalEventsProcessable--
		} else if oldState == types.EventStateWaiting {
			s.stats.TotalEventsWaiting--
		}
	}
}

// setEventState sets the state of an event in the scheduler queue
// (private method)
func setEventState(s *Scheduler, uuid uuid.UUID, state types.EventState) {
	if event, exists := s.events[uuid]; exists {
		if (state == types.EventStateDone || state == types.EventStateCancelled || state == types.EventStateError) && s.events[uuid].State == types.EventStateInProcess {
			s.CurrentRunningActions--
		}
		oldState := s.events[uuid].State
		event.State = state
		s.events[uuid].State = state
		updateSchedulerStats(s, oldState, state)
	} else {
		fmt.Printf("SetEventState: event '%s' not found\n", uuid)
	}
}

// SetEventState sets the state of an event in the scheduler queue
// Use it to set the state of an event by UUID
// (public method)
func SetEventState(e *types.Event, state types.EventState) {
	scheduler := e.Sched.(*Scheduler)
	if e == nil {
		scheduler.logger.Println("SetEventState: event is nil\n", e.UUID)
		return
	}

	scheduler.mutex.Lock()
	defer scheduler.mutex.Unlock()

	if (state == types.EventStateDone || state == types.EventStateCancelled || state == types.EventStateError) && scheduler.events[e.UUID].State == types.EventStateInProcess {
		scheduler.CurrentRunningActions--
	}
	oldState := scheduler.events[e.UUID].State
	scheduler.events[e.UUID].State = state
	e.State = state
	updateSchedulerStats(scheduler, oldState, state)
}

// removeEventAndDeps removes an event and the events that depends on it from the scheduler queue
func removeEventAndDeps(s *Scheduler, uuid uuid.UUID) {
	// Check for all the events that depend on this event
	for _, event := range s.events {
		for _, dependUUID := range event.DependOn {
			if dependUUID == uuid {
				// If the event depends on the event we are removing, set its state to cancelled
				// and remove it from the events map
				oldState := event.State
				event.State = types.EventStateCancelled
				updateSchedulerStats(s, oldState, event.State)
				delete(s.events, event.UUID)
			}
		}
	}
	// Remove the event from the events map
	delete(s.events, uuid)
}

func reschedule(s *Scheduler, event *types.Event) {
	// If the event is repeatable, schedule it again
	if event.RepeatEvery == 0 && event.RepeatTimes > 0 {
		// If the event is repeatable, schedule it again
		oldState := event.State
		event.State = types.EventStateProcessable
		updateSchedulerStats(s, oldState, event.State)
		event.RepeatTimes--
		err := schedule(s, event)
		if err != nil {
			s.logger.Fatal(err)
		}
	} else if event.RepeatEvery > 0 && event.RepeatTimes > 0 {
		// If the event is repeatable, schedule it again
		// Note: this if statement controls both the repeat every and repeat times
		//       If we need an event to be repeated for ever, we can set RepeatTimes to -1
		oldState := event.State
		event.State = types.EventStateProcessable
		updateSchedulerStats(s, oldState, event.State)
		event.Timestamp = time.Now()
		event.RepeatTimes--
		err := schedule(s, event)
		if err != nil {
			s.logger.Fatal(err)
		}
	} else if event.RepeatEvery >= 0 && event.RepeatTimes == -1 {
		// If the event is repeatable, schedule it again (for ever)
		oldState := event.State
		event.State = types.EventStateProcessable
		updateSchedulerStats(s, oldState, event.State)
		event.Timestamp = time.Now()
		err := schedule(s, event)
		if err != nil {
			s.logger.Fatal(err)
		}
	} else {
		// If the event is not repeatable, remove it from the events map
		delete(s.events, event.UUID)
	}

}

func isProcessable(s *Scheduler, event *types.Event, config *ProcessConfig) bool {
	// Check if all dependencies are met
	canProcess := true
	for _, dependUUID := range event.DependOn {
		if depEvent, exists := s.events[dependUUID]; exists && depEvent.State != types.EventStateDone {
			if config.DebugLevel > 1 {
				s.logger.Printf("Event '%s' with name '%s' can't be processed because it depends on event '%s', which is not done yet\n", event.UUID, event.Name, dependUUID)
				s.logger.Printf("Event '%s' with name '%s' is in state %d\n", dependUUID, depEvent.Name, depEvent.State)
				if config.DebugLevel > 2 {
					s.logger.Println("Event body: ", depEvent)
				}
			}
			if dependUUID != event.UUID && dependUUID != zeroUUID {
				canProcess = false
			}
			break
		}
	}
	return canProcess
}

// Process() processes the events in a queue
// it's parametric, so it requires a ProcessConfig struct
// Use it to start the scheduler
func (s *Scheduler) Process(config ProcessConfig) {
	// Init local variables
	var previousAverage time.Duration
	var averageWaitingTime time.Duration

	// Events processing loop
	for {
		// Check if the scheduler has been shutdown
		if s.state == SchedulerStateShutdown {
			return
		} else if s.state == SchedulerStatePaused {
			// If the scheduler is paused, wait for a second and continue
			time.Sleep(1 * time.Second)
			continue
		}
		if averageWaitingTime > 0 {
			// If we have an average waiting time, wait for it
			time.Sleep(averageWaitingTime)
		}
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
		var event types.Event
		element, ok := s.q.Next() // workaround to get all events
		event = element.(types.Event)
		if !ok {
			// If the event is not ok, remove it from the events map
			// and continue to the next event
			delete(s.events, event.UUID)
			if config.DebugLevel > 0 {
				s.logger.Println("The element presented a problem: ", event)
			}
			s.mutex.Unlock()
			continue
		}

		// If the event in being processed then continue to the next event
		if s.events[event.UUID].State == types.EventStateInProcess {
			if config.ActionTimeout > 0 {
				if time.Now().After(event.Timeout) {
					oldState := event.State
					event.State = types.EventStateError
					updateSchedulerStats(s, oldState, event.State)
				}
			}
			if config.DebugLevel > 0 {
				s.logger.Println("Event in process: ", event)
			}
			err := schedule(s, &event)
			if err == nil {
				s.mutex.Unlock()
				continue
			} else {
				s.logger.Println(err)
			}
		}

		// If the event is cancelled, remove it from the events map
		// and continue to the next event
		if s.events[event.UUID].State == types.EventStateCancelled || s.events[event.UUID].State == types.EventStateError {
			if event.State == types.EventStateError {
				s.logger.Println("The element presented an error: ", event)
			}
			removeEventAndDeps(s, event.UUID)
			s.mutex.Unlock()
			continue
		}

		// If the event is done, check if it needs to be repeated
		if s.events[event.UUID].State == types.EventStateDone {
			// Event is completed, check if it needs to be repeated
			reschedule(s, &event)
			s.mutex.Unlock()
			continue
		}

		// Check if all dependencies are met
		canProcess := isProcessable(s, &event, &config)

		if canProcess &&
			time.Now().After(event.Timestamp.Add(time.Duration(time.Duration(event.RepeatEvery)*time.Millisecond))) {

			// If it can be processed, process it
			if config.CheckEvent {
				s.logger.Printf("Processing event: %s (UUID: %s)\n", event.Name, event.UUID)
				s.logger.Println("Event body: ", event)
			}

			// Set the event state to in process
			if s.CurrentRunningActions < config.MaxConcurrentActions {
				oldState := event.State
				event.State = types.EventStateInProcess
				updateSchedulerStats(s, oldState, event.State)
			}
			event.Timeout = time.Now().Add(time.Duration(config.ActionTimeout) * time.Second)

			// Execute the action
			errCh := make(chan error)
			if config.ExecuteAction && event.Action != nil {
				if averageWaitingTime > 0 {
					// reset average waiting time
					averageWaitingTime = 0
				}
				// Schedule the event again with its new state
				err := schedule(s, &event)
				if event.State != types.EventStateInProcess {
					// If we reached the maximum number of concurrent actions, reschedule the event
					// and continue to the next event
					s.mutex.Unlock()
					continue
				}

				if err == nil {
					// Increment the number of running actions
					s.CurrentRunningActions++

					// Process the event in a goroutine
					go processEvent(event, errCh)
				}
			} else {
				oldState := event.State
				event.State = types.EventStateProcessable
				updateSchedulerStats(s, oldState, event.State)
			}

			if config.ReturnIfFound {
				s.mutex.Unlock()
				return
			}
		} else {
			// If it can't be processed yet, then use it to calculate average waiting time
			if canProcess {
				// calculate average waiting time
				targetTime := event.Timestamp.Add(time.Duration(event.RepeatEvery) * time.Millisecond)
				waitingTime := time.Until(targetTime) // current waiting time

				// compute the new average waiting time considering current waiting time and previous average
				averageWaitingTime := (waitingTime + previousAverage) / 2

				// store the new average for future computations
				previousAverage = averageWaitingTime
			}

			// If it can't be processed, append it back to the queue
			err := schedule(s, &event)
			if err != nil {
				s.logger.Fatal(err)
			}
		}
		s.mutex.Unlock()
	}
}
