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
	shutdownDiagnosticsMaxTime = 10 * time.Second
	shutdownDiagnosticsMessage = "PostgreSQL shutdown diagnostics"
)

var (
	shutdownDiagnosticsProcRoot = "/proc"
)

func logShutdownDiagnostics(ctx context.Context) {
	logShutdownDiagnosticsWithLogger(ctx, log.FromContext(ctx))
}

func logShutdownDiagnosticsWithLogger(ctx context.Context, contextLogger log.Logger) {
	diagCtx, cancel := context.WithTimeout(context.Background(), shutdownDiagnosticsMaxTime)
	defer cancel()

	contextLogger.Info(shutdownDiagnosticsMessage,
		"collectTime", time.Now().UTC().Format(time.RFC3339),
		"processes", collectProcDiagnostics(diagCtx, shutdownDiagnosticsProcRoot))
}

type procDiagnostics struct {
	PID          string                        `json:"pid"`
	PPID         string                        `json:"ppid,omitempty"`
	State        string                        `json:"state,omitempty"`
	StatusError  string                        `json:"statusError,omitempty"`
	Wchan        string                        `json:"wchan,omitempty"`
	WchanError   string                        `json:"wchanError,omitempty"`
	Command      string                        `json:"command,omitempty"`
	CommandError string                        `json:"commandError,omitempty"`
	Files        map[string]procFileDiagnostic `json:"files"`
}

type procFileDiagnostic struct {
	Lines []string `json:"lines,omitempty"`
	Error string   `json:"error,omitempty"`
}

func collectProcDiagnostics(ctx context.Context, procRoot string) []procDiagnostics {
	pids, err := filepath.Glob(filepath.Join(procRoot, "[0-9]*"))
	if err != nil {
		return []procDiagnostics{{
			Files: map[string]procFileDiagnostic{
				"proc": {Error: err.Error()},
			},
		}}
	}

	processes := make([]procDiagnostics, 0, len(pids))
	for _, pidDir := range pids {
		if err := ctx.Err(); err != nil {
			return append(processes, procDiagnostics{
				Files: map[string]procFileDiagnostic{
					"collection": {Error: err.Error()},
				},
			})
		}

		pid := filepath.Base(pidDir)
		status, statusErr := readStatusFields(filepath.Join(pidDir, "status"))
		wchan, wchanErr := readProcFile(filepath.Join(pidDir, "wchan"))
		command, commandErr := readProcFile(filepath.Join(pidDir, "comm"))

		processes = append(processes, procDiagnostics{
			PID:          pid,
			PPID:         status["PPid"],
			StatusError:  errorString(statusErr),
			State:        status["State"],
			Wchan:        strings.TrimSpace(wchan),
			WchanError:   errorString(wchanErr),
			Command:      strings.TrimSpace(command),
			CommandError: errorString(commandErr),
			Files: map[string]procFileDiagnostic{
				"cmdline": readProcLines(filepath.Join(pidDir, "cmdline"), 0, true),
				"comm":    readProcLines(filepath.Join(pidDir, "comm"), 0, false),
				"status":  readProcLines(filepath.Join(pidDir, "status"), 90, false),
				"wchan":   readProcLines(filepath.Join(pidDir, "wchan"), 0, false),
				"io":      readProcLines(filepath.Join(pidDir, "io"), 0, false),
				"limits":  readProcLines(filepath.Join(pidDir, "limits"), 0, false),
				// stack and syscall are often ptrace/capability gated; log read errors inline.
				"syscall": readProcLines(filepath.Join(pidDir, "syscall"), 0, false),
				"stack":   readProcLines(filepath.Join(pidDir, "stack"), 0, false),
				"sched":   readProcLines(filepath.Join(pidDir, "sched"), 35, false),
			},
		})
	}
	return processes
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

func readProcLines(fileName string, maxLines int, nullSeparated bool) procFileDiagnostic {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return procFileDiagnostic{Error: err.Error()}
	}

	content := string(data)
	if nullSeparated {
		content = strings.ReplaceAll(content, "\x00", " ")
	}
	result := procFileDiagnostic{}
	for lineNumber, line := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		if maxLines > 0 && lineNumber >= maxLines {
			break
		}
		result.Lines = append(result.Lines, line)
	}
	return result
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%v", err)
}
