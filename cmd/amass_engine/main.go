package main

import (
	//	"fmt"
	"log"
	"os"

	"github.com/owasp-amass/engine/api/graphql/server"
	"github.com/owasp-amass/engine/events"
)

func main() {

	logger := log.New(os.Stdout, "Test: ", log.Ldate|log.Ltime|log.Lshortfile)
	scheduler := events.NewScheduler(logger)

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
