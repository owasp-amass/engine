# Events Scheduler

The Events Scheduler is a component of the Amass project that provides a centralized mechanism to manage, schedule, and process events. It is designed to be a generic scheduler that can be used in any application that requires event scheduling and processing.

## Table of Contents

- [Events Scheduler](#events-scheduler)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Main Scheduler](#main-scheduler)
    - [Main Scheduler Public API](#main-scheduler-public-api)
      - [Functions:](#functions)
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

The Events Scheduler is a component of the Amass project that provides a centralized mechanism to manage, schedule, and process events.

It offers a centralized events scheduler called the Main Scheduler, which is responsible for managing, scheduling, and processing events. The Main Scheduler is designed to "talk" (through events) to other components of the Amass engine, such as the the GraphQL interface, the Event Plugins adn Pipelines and the engine itself that can use the Main Scheduler to schedule System events like checking if we are consuming too much RAM or too much disk space and other systems level events.

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

## Main Scheduler

As mentioned above the Main Scheduler is designed to be a Singleton pattern that can be used by all components of the Amass engine. It has a public API that can be used by other components to schedule events on the Main Scheduler.

## Main Scheduler Public API

This API is crafted to meet Amass requirements, presenting functions that handle event life-cycles, from initialization to processing.

### Functions

#### 1. MainSchedulerInit()

**Description:**  
Initializes the main scheduler.

This method should be called by the Initialization process of the Amass engine.

**Usage:**

```go
MainSchedulerInit()
```

#### 2. MainSchedulerSchedule(e *Event) error

**Description:**  
Schedules an event on the main scheduler. If there are errors during the scheduling process, the function returns an error.

**Parameters:**

- `e *Event`: The event to be scheduled.

**Returns:**

- `error`: Returns an error if the scheduling process encounters issues.

**Usage:**

```go
event := &Event{ /*... attributes ...*/ }
err := MainSchedulerSchedule(event)
if err != nil {
    // Handle error
}
```

#### 3. MainSchedulerCancel(uuid uuid.UUID)

**Description:**

Cancels a scheduled event in the main scheduler based on its UUID.

**Parameters:**

- `uuid uuid.UUID`: The UUID of the event to be cancelled.

**Usage:**

```go
MainSchedulerCancel(someUUID)
```

#### 4. MainSchedulerCancelAll()

**Description:**  
Cancels all scheduled events in the main scheduler.

**Usage:**

```go
MainSchedulerCancelAll()
```

#### 5. MainSchedulerSetEventState(uuid uuid.UUID, state EventState)

**Description:**  
Sets the state of an event in the main scheduler.

This method should be called by every Amass component and pipeline that is responsible for processing events.
For these components, this method should be called when the event processing is done. This is vital if the event process() configuration has been set to NOT have a timeout for events being processed.

**Parameters:**

- `uuid uuid.UUID`: The UUID of the event whose state is to be set.
- `state EventState`: The desired state to be set.

**Usage:**

```go
MainSchedulerSetEventState(someUUID, StateDone)
```

#### 6. MainSchedulerProcess()

**Description:**  
Processes the events in the main scheduler queue based on a predefined process configuration.

This method should be called by the Initialization process of the Amass engine.

**Usage:**

```go
MainSchedulerProcess()
```

Based on the provided code, I'll draft the technical documentation for the `events_scheduler` package:

---

## Events Scheduler Technical Documentation

### Introduction

`events_scheduler` is a package responsible for creating, scheduling, and processing events. This package defines the structures and mechanisms to manage event dependencies, priority, and state, allowing you to create flexible event-driven systems.

### Structures

#### EventType

Enumerates the types of events.

- `SystemType`: System events.
- `EventTypeLog`: Used for logging messages.
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

To use the `events_scheduler` package:

1. Initialize the scheduler using either `MainSchedulerInit()` for the main scheduler or `NewScheduler()` for sub-schedulers.
2. Create events and add them to the scheduler.
3. Configure the event processing using the `ProcessConfig` structure.
4. Process events using the configured parameters.
