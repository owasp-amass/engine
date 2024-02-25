// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/owasp-amass/engine"
	"github.com/owasp-amass/engine/plugins"
)

func main() {
	var logdir string
	flag.StringVar(&logdir, "log-dir", "", "path to the log directory")
	flag.Parse()

	if logdir != "" {
		if err := os.MkdirAll(logdir, 0640); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create the log directory: %v", err)
		}
	}

	filename := fmt.Sprintf("amass_engine_%s.log", time.Now().Format("2006-01-02T15:04:05"))
	f, err := os.OpenFile(filepath.Join(logdir, filename), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log file: %v", err)
	}
	defer f.Close()

	l := slog.New(slog.NewJSONHandler(f, nil))
	e, err := engine.NewEngine(l)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start the engine: %v", err)
		os.Exit(1)
	}
	defer e.Shutdown()

	if err := plugins.LoadAndStartPlugins(e.Registry); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start the plugins: %v", err)
		os.Exit(1)
	}

	if err := e.Registry.BuildPipelines(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build the handler pipelines: %v", err)
		os.Exit(1)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(quit)
	<-quit
	l.Info("Terminating the collection engine")
}
