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

	var out strings.Builder
	fmt.Fprintf(&out, "collect_time=%s\n", time.Now().UTC().Format(time.RFC3339))
	appendProcessSummary(diagCtx, &out, shutdownDiagnosticsProcRoot)
	appendProcOutput(diagCtx, &out, shutdownDiagnosticsProcRoot)

	for _, line := range strings.Split(strings.TrimRight(out.String(), "\n"), "\n") {
		contextLogger.Info("PostgreSQL shutdown diagnostics", "line", line)
	}
}

func appendProcessSummary(ctx context.Context, out *strings.Builder, procRoot string) {
	out.WriteString("--- process summary ---\n")
	pids, err := filepath.Glob(filepath.Join(procRoot, "[0-9]*"))
	if err != nil {
		fmt.Fprintf(out, "process listing failed: %v\n", err)
		return
	}

	out.WriteString("    PID    PPID STATE WCHAN                            COMMAND\n")
	for _, pidDir := range pids {
		if err := ctx.Err(); err != nil {
			fmt.Fprintf(out, "process listing stopped: %v\n", err)
			return
		}

		status := readStatusFields(filepath.Join(pidDir, "status"))
		fmt.Fprintf(out, "%7s %7s %-5s %-32s %s\n",
			filepath.Base(pidDir),
			status["PPid"],
			status["State"],
			strings.TrimSpace(readProcFile(filepath.Join(pidDir, "wchan"))),
			strings.TrimSpace(readProcFile(filepath.Join(pidDir, "comm"))),
		)
	}
}

func readStatusFields(fileName string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(readProcFile(fileName), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			result[key] = strings.TrimSpace(value)
		}
	}
	return result
}

func readProcFile(fileName string) string {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return fmt.Sprintf("%v", err)
	}
	return string(data)
}

func appendProcOutput(ctx context.Context, out *strings.Builder, procRoot string) {
	out.WriteString("--- /proc all pids ---\n")
	pids, err := filepath.Glob(filepath.Join(procRoot, "[0-9]*"))
	if err != nil {
		fmt.Fprintf(out, "cannot list %s: %v\n", procRoot, err)
		return
	}

	for _, pidDir := range pids {
		if err := ctx.Err(); err != nil {
			fmt.Fprintf(out, "diagnostic collection stopped: %v\n", err)
			return
		}

		fmt.Fprintf(out, "=== pid %s ===\n", filepath.Base(pidDir))
		appendProcFile(out, "cmdline", filepath.Join(pidDir, "cmdline"), 0, true)
		appendProcFile(out, "comm", filepath.Join(pidDir, "comm"), 0, false)
		appendProcFile(out, "status", filepath.Join(pidDir, "status"), 90, false)
		appendProcFile(out, "wchan", filepath.Join(pidDir, "wchan"), 0, false)
		appendProcFile(out, "io", filepath.Join(pidDir, "io"), 0, false)
		appendProcFile(out, "limits", filepath.Join(pidDir, "limits"), 0, false)
		appendProcFile(out, "syscall", filepath.Join(pidDir, "syscall"), 0, false)
		appendProcFile(out, "stack", filepath.Join(pidDir, "stack"), 0, false)
		appendProcFile(out, "sched head", filepath.Join(pidDir, "sched"), 35, false)
	}
}

func appendProcFile(out *strings.Builder, title, fileName string, maxLines int, nullSeparated bool) {
	fmt.Fprintf(out, "--- %s ---\n", title)
	data, err := os.ReadFile(fileName)
	if err != nil {
		fmt.Fprintf(out, "%v\n", err)
		return
	}

	content := string(data)
	if nullSeparated {
		content = strings.ReplaceAll(content, "\x00", " ")
	}
	if maxLines > 0 {
		lines := strings.SplitAfter(content, "\n")
		if len(lines) > maxLines {
			content = strings.Join(lines[:maxLines], "")
		}
	}
	out.WriteString(content)
	if !strings.HasSuffix(content, "\n") {
		out.WriteString("\n")
	}
}
