// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/owasp-amass/engine"
	"github.com/owasp-amass/engine/plugins"
)

func main() {
	pid := os.Getpid()
	pidstr := strconv.Itoa(pid)
	filename := fmt.Sprintf("amass-%s.log", pidstr)
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
		os.Exit(1)
	}
	defer file.Close()

	l := log.New(file, "", log.Lmicroseconds)
	e, err := engine.NewEngine(l)
	if err != nil {
		log.Fatalf("Failed to start the engine: %v", err)
		os.Exit(1)
	}
	defer e.Shutdown()

	if err := plugins.LoadAndStartPlugins(e.Registry); err != nil {
		l.Printf("Failed to start the plugins: %v", err)
		os.Exit(1)
	}

	if err := e.Registry.BuildPipelines(); err != nil {
		l.Printf("Failed to build the handler pipelines: %v", err)
		os.Exit(1)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(quit)
	<-quit
}
