package main

import (
	//	"fmt"
	"github.com/owasp-amass/engine/api/graphql/server"
	"github.com/owasp-amass/engine/events"
)

func main() {

	scheduler := events.NewScheduler()

	config := events.ProcessConfig{
		ExitWhenEmpty:        false,
		CheckEvent:           false,
		ExecuteAction:        true,
		ReturnIfFound:        false,
		DebugLevel:           0,
		ActionTimeout:        0,
		MaxConcurrentActions: 8,
	}

	go func(config events.ProcessConfig) {
		scheduler.Process(config)
		/*
			err := scheduler.Process(config)
			if err != nil {
				errCh <- err
			}
		*/
	}(config)

	server := server.NewServer(scheduler)
	server.Start()

	// Wait

}
