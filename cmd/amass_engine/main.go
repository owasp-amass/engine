package main

import (
	//	"fmt"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/owasp-amass/engine/api/graphql/server"
	"github.com/owasp-amass/engine/registry"
	"github.com/owasp-amass/engine/scheduler"
	"github.com/owasp-amass/engine/sessions"
)

func main() {
	pid := os.Getpid()
	pidStr := strconv.Itoa(pid)
	filename := fmt.Sprintf("Amass-%s.log", pidStr)
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed to open log file: %v", err)
	}
	defer file.Close()

	// Step 2: Create a new logger instance using `log.New()`
	logger := log.New(file, "custom-prefix: ", log.LstdFlags)
	//logger := log.New(os.Stdout, "Test: ", log.Ldate|log.Ltime|log.Lshortfile)
	sessionManager := sessions.NewStorage(logger)
	Registry := registry.NewRegistry(logger)
	Scheduler := scheduler.NewScheduler(logger, Registry)

	config := scheduler.ProcessConfig{
		ExitWhenEmpty:        false,
		CheckEvent:           false,
		ExecuteAction:        true,
		ReturnIfFound:        false,
		DebugLevel:           0,
		ActionTimeout:        0,
		MaxConcurrentActions: 8,
	}

	go func(config scheduler.ProcessConfig) {
		Scheduler.Process(config)
		/*
			err := scheduler.Process(config)
			if err != nil {
				errCh <- err
			}
		*/
	}(config)

	server := server.NewServer(logger, Scheduler, sessionManager)
	fmt.Println("Started server...")
	server.Start()

	// Wait

}
