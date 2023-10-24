# Events Scheduler

The Events Scheduler is a component of the Amass project that provides a mechanism to manage, schedule, and process events. It is designed to be a generic scheduler that can be used in any application that requires event scheduling and processing.

## Table of Contents

- [Events Scheduler](#events-scheduler)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Events Scheduler Technical Documentation](#events-scheduler-technical-documentation)
    - [Introduction](#introduction)
    - [Structures](#structures)
      - [EventType](#eventtype)
      - [EventState](#eventstate)
      - [Event](#event)
      - [Scheduler](#scheduler)
      - [ProcessConfig](#processconfig)
    - [Usage](#usage)

## Overview

The Events Scheduler offers functionalities to create events schedulers within Amass events which can be used for managing, scheduling, and processing events. The Scheduler API is designed to "talk" (through events) to other components of the Amass engine, such as the the GraphQL interface, the Event processing Pipelines and the engine itself that can use the Scheduler to schedule System events like checking if we are consuming too much RAM or too much disk space and other systems level events.

The Events Scheduler also offers an API to allow Pipelines (for example) to have their own schedulers that can be used to schedule events that are specific to the Pipeline. These schedulers are called Local Schedulers and they are managed by the component who allocate them. For example, the Pipeline component is responsible for allocating and managing the Local Schedulers for the Pipeline.

The events scheduler code is a concurrency-safe event scheduling system that uses a priority queue. Here's a summary of its features:

1. **Components and Dependencies**

   - The package uses external dependencies such as `queue` (a priority queue) and `uuid` (for generating unique identifiers).
   - It uses mutexes for synchronization to ensure that multiple goroutines can safely interact with the events and the scheduler.

2. **Scheduler**

   - The `Scheduler` type has methods for scheduling events, canceling events, setting event states, and processing events.
   - Each event has a unique UUID, priority, state, dependencies on other events, and other attributes.
   - Events can depend on the completion of other events. They won't be processed until their dependencies are fulfilled.

3. **Event Attributes and States**

   - Each event can be in one of several states: `StateWaiting`, `StateProcessable`, `StateDone`, etc.
   - Events can be repeatable with attributes like `RepeatEvery` (how often to repeat) and `RepeatTimes` (how many times to repeat).
   - If an event has no action associated with it, a default action is provided.

4. **Processing Loop**

   - The scheduler's `Process` method contains a loop that processes events based on their priority and dependencies.
   - If the queue is empty, it either exits (based on configuration) or waits and continues.
   - When an event is retrieved from the queue, the system checks if it's already being processed, if it's canceled, if it's completed and needs to be repeated, or if it has unsatisfied dependencies.
   - If an event's dependencies are met, it's processed.

5. **Error Handling and Debugging**

   - At the moment there are multiple placeholders (`TODO`) for integrating logging into the system for better debugging and error handling.
   - Events that present problems or errors are logged, and appropriate actions are taken, like re-scheduling or removal.

6. **Potential Areas for Improvement/Consideration**

   - While the system supports event dependencies, at the moment it doesn't handle circular dependencies or provide a way to detect them. This is a goal for future development.
   - The system lacks a mechanism for event persistence, meaning that if the system crashes or restarts, all scheduled events could be lost. This may not be a problem for the way Amass is used at the moment, but it may become a requirement for future development.

Overall, the events scheduler provides a solid foundation for an event-driven system with priority and dependencies. With some refinements, it could be a robust solution for a variety of scheduling needs.

## Events Scheduler Technical Documentation

### Introduction

`events` is a package responsible for creating, scheduling, and processing events. This package defines the structures and mechanisms to manage event dependencies, priority, and state, allowing you to create flexible event-driven systems.

### Structures

All structures are defined in the `datatypes.go` file.

#### EventType

Enumerates the types of events.

- `SystemType`: System events.
- `EventTypeLog`: Used for logging messages.
- `EventTypeCustom`: Used for custom events.
- `EventTypeSay`: Used for printing debug messages to the console.
- (Note: Additional event types can be added as needed.)

#### EventState

Enumerates the states of events.

- `StateDefault`: Default state, usually set when the event is created.
- `StateProcessable`: Event can be processed; all dependencies are met.
- `StateWaiting`: Event is waiting due to unmet dependencies.
- `StateDone`: Event has been processed.
- `StateInProcess`: Event is currently being processed.
- `StateCancelled`: Event was cancelled.
- `StateError`: Event encountered an error.

#### Event

Represents an individual event with its associated attributes and functionalities. It is the primary structure for managing events within the system.
Attributes:

- `UUID`: Unique identifier for the event.
- `Session`: Identifier for the session.
- `Name`: Event name.
- `Timestamp`: Time the event was created.
- `Type`: The type of event.
- `State`: Current state of the event.
- `DependOn`: UUIDs of events this event is dependent on.
- `Action`: A handler function for the event.
- `Priority`: Priority of the event.
- `RepeatEvery`: Interval to repeat the event.
- `RepeatTimes`: Number of repetitions for the event.
- `Data`: Arbitrary data attached to the event.
- `timeout`: Time after which the event is cancelled if unprocessed.
- `s`: Reference to the scheduler creating the event.

#### Scheduler

Manages the scheduling and processing of events. There are two types: Main scheduler (a singleton) and Sub schedulers.
Attributes:

- `q`: Queue storing events.
- `mutex`: Ensures thread-safety when accessing the queue.
- `events`: A map for rapid lookup of events by their UUID.
- `CurrentRunningActions`: Tracks the number of currently running actions.

#### ProcessConfig

Configuration structure used during the event processing phase.
Attributes:

- `ExitWhenEmpty`: Flag to exit processing when the queue is empty.
- `CheckEvent`: Flag to check if an event can be processed.
- `ExecuteAction`: Flag to execute the action.
- `ReturnIfFound`: Flag to return from processing if an event is found.
- `DebugInfo`: Flag to print debugging information.
- `ActionTimeout`: Timeout for executing an action.
- `MaxConcurrentActions`: Maximum allowed concurrent actions.

### Usage

To use the `events` package:

1. Initialize a scheduler using `NewScheduler()`.
   - For example, to create a main scheduler:

     ```go
     logFacility := log.New(os.Stderr, "", log.LstdFlags)
     scheduler := events.NewScheduler(LogFacility)
     ```

2. Create events and add them to the scheduler.
   - For example, to create a new event:

     ```go
     event := &Event { Name: "MyEvent", Type: events.EventTypeLog, Priority: 1}
     ```

   - To add the event to the scheduler:

     ```go
     scheduler.Schedule(event)
     ```

3. Configure the event processing using the `ProcessConfig` structure.
   - For example, to configure the processing:

     ```go
     config := &ProcessConfig { ExitWhenEmpty: true, CheckEvent: true, ExecuteAction: true, ReturnIfFound: false, DebugInfo: false, ActionTimeout: 10, MaxConcurrentActions: 10 }
     ```

4. Process events using the configured parameters.
   - For example, to process events:

     ```go
     go func(e Event) {
         err := scheduler.Process(config)
         if err != nil {
            errCh <- err
         }
     }(event)
     ```

5. To Shutdown the scheduler:

   ```go
   scheduler.Shutdown()
   ```

If you need to cancel an event, you can use the `CancelEvent` method:

```go
scheduler.CancelEvent(event.UUID)
```

If you need to set the state of an event, you can use the `SetEventState` method:

```go
scheduler.SetEventState(event.UUID, events.StateDone)
```

If you need to set the state of an event from a package that has no knowledge of the scheduler, you can use the `SetEventState` method as follows:

```go
// Please note the references to the package name and the event type.
events.SetState(&event, events.StateDone)
```

### Handling of Actions

The `Action` attribute of an event is a function that takes an event as a parameter and returns an error. The function is executed when the event is processed. If the event has no action, a default action is used.

There are different ways to assign an action to an event:

- Assign a function to the `Action` attribute of the event.
  This means literally assigning a function to the `Action` attribute of the event. For example:

  ```go
   event.Type = events.EventTypeCustom
   event.Action = func(e *Event) error {
         // Do something

         // Very important: At the end of your function, set the state of the event to StateDone!
         events.SetState(e, events.StateDone)
         return nil
   }
   ```

- Assign a function to the `Action` attribute of the event using a function literal.
  For example:
  
  ```go
   event.Type = events.EventTypeCustom
   event.Action = MyFunction
   ```

- Setting up the EventType only
  For example:

  ```go
   event.Type = events.EventTypeLog
   ```

   This will make The Event Scheduler assign the appropriate Action to your event based on the EventType.

#### Order of eventType and Action assignment

Give we have multiple choices, we have established an order of priority for the assignment of the Action to the event. The order is as follows:

1. If the event has an Action assigned to it, that Action will be used, aka if Action is NOT nil. (Highest priority)
2. If the event has an EventType assigned to it, the appropriate Action will be assigned to the event. (Medium priority)
3. If the event has no Action and no EventType assigned to it, the default Action will be assigned to the event. (Lowest priority)
