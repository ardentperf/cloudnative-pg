/*
Copyright © contributors to CloudNativePG, established as
CloudNativePG a Series of LF Projects, LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
*/

package postgres

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudnative-pg/machinery/pkg/log"
)

const (
	shutdownDiagnosticsLeadTime = 30 * time.Second
	shutdownDiagnosticsMaxTime  = 10 * time.Second
	shutdownDiagnosticsMessage  = "PostgreSQL shutdown diagnostics"
)

var (
	shutdownDiagnosticsProcRoot = "/proc"
	runShutdownDiagnostics      = logShutdownDiagnostics
)

func scheduleShutdownDiagnostics(ctx context.Context, timeout time.Duration) context.CancelFunc {
	delay, ok := shutdownDiagnosticsDelay(timeout)
	if !ok {
		return func() {}
	}
	return scheduleShutdownDiagnosticsAfter(ctx, delay)
}

func scheduleShutdownDiagnosticsAfter(ctx context.Context, delay time.Duration) context.CancelFunc {
	scheduleCtx, cancel := context.WithCancel(context.Background())
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()

		select {
		case <-timer.C:
			runShutdownDiagnostics(ctx)
		case <-scheduleCtx.Done():
		}
	}()
	return cancel
}

func shutdownDiagnosticsDelay(timeout time.Duration) (time.Duration, bool) {
	if timeout <= 2*time.Second {
		return 0, false
	}
	if timeout <= 2*time.Minute {
		return timeout * 3 / 4, true
	}
	return timeout - shutdownDiagnosticsLeadTime, true
}

func logShutdownDiagnostics(ctx context.Context) {
	contextLogger := log.FromContext(ctx)
	diagCtx, cancel := context.WithTimeout(context.Background(), shutdownDiagnosticsMaxTime)
	defer cancel()

	contextLogger.Info(shutdownDiagnosticsMessage,
		"section", "collection",
		"event", "start",
		"collectTime", time.Now().UTC().Format(time.RFC3339))
	logProcessSummary(diagCtx, contextLogger, shutdownDiagnosticsProcRoot)
	logProcOutput(diagCtx, contextLogger, shutdownDiagnosticsProcRoot)
}

func logProcessSummary(ctx context.Context, contextLogger log.Logger, procRoot string) {
	pids, err := filepath.Glob(filepath.Join(procRoot, "[0-9]*"))
	if err != nil {
		contextLogger.Info(shutdownDiagnosticsMessage,
			"section", "process_summary",
			"error", err.Error())
		return
	}

	for _, pidDir := range pids {
		if err := ctx.Err(); err != nil {
			contextLogger.Info(shutdownDiagnosticsMessage,
				"section", "process_summary",
				"error", err.Error())
			return
		}

		pid := filepath.Base(pidDir)
		status, statusErr := readStatusFields(filepath.Join(pidDir, "status"))
		wchan, wchanErr := readProcFile(filepath.Join(pidDir, "wchan"))
		command, commandErr := readProcFile(filepath.Join(pidDir, "comm"))

		contextLogger.Info(shutdownDiagnosticsMessage,
			"section", "process_summary",
			"pid", pid,
			"ppid", status["PPid"],
			"statusError", errorString(statusErr),
			"state", status["State"],
			"wchan", strings.TrimSpace(wchan),
			"wchanError", errorString(wchanErr),
			"command", strings.TrimSpace(command),
			"commandError", errorString(commandErr),
		)
	}
}

func readStatusFields(fileName string) (map[string]string, error) {
	result := make(map[string]string)
	content, err := readProcFile(fileName)
	if err != nil {
		return result, err
	}
	for _, line := range strings.Split(content, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			result[key] = strings.TrimSpace(value)
		}
	}
	return result, nil
}

func readProcFile(fileName string) (string, error) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func logProcOutput(ctx context.Context, contextLogger log.Logger, procRoot string) {
	pids, err := filepath.Glob(filepath.Join(procRoot, "[0-9]*"))
	if err != nil {
		contextLogger.Info(shutdownDiagnosticsMessage,
			"section", "proc",
			"error", err.Error())
		return
	}

	for _, pidDir := range pids {
		if err := ctx.Err(); err != nil {
			contextLogger.Info(shutdownDiagnosticsMessage,
				"section", "proc",
				"error", err.Error())
			return
		}

		pid := filepath.Base(pidDir)
		logProcFile(contextLogger, pid, "cmdline", filepath.Join(pidDir, "cmdline"), 0, true)
		logProcFile(contextLogger, pid, "comm", filepath.Join(pidDir, "comm"), 0, false)
		logProcFile(contextLogger, pid, "status", filepath.Join(pidDir, "status"), 90, false)
		logProcFile(contextLogger, pid, "wchan", filepath.Join(pidDir, "wchan"), 0, false)
		logProcFile(contextLogger, pid, "io", filepath.Join(pidDir, "io"), 0, false)
		logProcFile(contextLogger, pid, "limits", filepath.Join(pidDir, "limits"), 0, false)
		// stack and syscall are often ptrace/capability gated; log read errors inline.
		logProcFile(contextLogger, pid, "syscall", filepath.Join(pidDir, "syscall"), 0, false)
		logProcFile(contextLogger, pid, "stack", filepath.Join(pidDir, "stack"), 0, false)
		logProcFile(contextLogger, pid, "sched", filepath.Join(pidDir, "sched"), 35, false)
	}
}

func logProcFile(
	contextLogger log.Logger,
	pid string,
	field string,
	fileName string,
	maxLines int,
	nullSeparated bool,
) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		contextLogger.Info(shutdownDiagnosticsMessage,
			"section", "proc",
			"pid", pid,
			"field", field,
			"error", err.Error())
		return
	}

	content := string(data)
	if nullSeparated {
		content = strings.ReplaceAll(content, "\x00", " ")
	}
	for lineNumber, line := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		if maxLines > 0 && lineNumber >= maxLines {
			break
		}
		contextLogger.Info(shutdownDiagnosticsMessage,
			"section", "proc",
			"pid", pid,
			"field", field,
			"lineNumber", lineNumber+1,
			"line", line)
	}
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%v", err)
}
