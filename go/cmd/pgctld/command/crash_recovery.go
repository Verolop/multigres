// Copyright 2026 Supabase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package command

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/multigres/multigres/go/common/constants"
	"github.com/multigres/multigres/go/services/pgctld"
	"github.com/multigres/multigres/go/tools/executil"
	"github.com/multigres/multigres/go/tools/retry"
)

// postgresAlreadyRunningPattern matches the postgres error reported when the
// postmaster.pid lock file is held. After a postmaster crash (kill -9 of a single
// PID, OOM, segfault), orphaned worker processes (writer, checkpointer,
// walreceiver, bgwriter) keep the SHM segment attached for ~1-5s while they
// detect parent death via PostmasterIsAlive() and exit. The same error is
// reported during that window even though postgres is not actually running.
var postgresAlreadyRunningPattern = regexp.MustCompile(`lock file ".*" already exists`)

// isPostgresCleanlyStopped checks if PostgreSQL is in a clean shutdown state.
// Returns true if state is "shut down" or "shut down in recovery", false otherwise.
func isPostgresCleanlyStopped(ctx context.Context) (bool, error) {
	cmd := executil.Command(ctx, "pg_controldata", pgctld.PostgresDataDir())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("pg_controldata failed: %w (output: %s)", err, string(output))
	}

	outputStr := string(output)
	clusterStateStr := extractClusterState(outputStr)

	// Clean states: "shut down", "shut down in recovery"
	// Anything else means we should try crash recovery
	cleanlyStopped := clusterStateStr == "shut down" || clusterStateStr == "shut down in recovery"

	return cleanlyStopped, nil
}

// extractClusterState extracts the cluster state from pg_controldata output
func extractClusterState(output string) string {
	for line := range strings.SplitSeq(output, "\n") {
		if strings.Contains(line, "Database cluster state:") {
			// Format: "Database cluster state:               in production"
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return "unknown"
}

// runCrashRecovery performs crash recovery in single-user mode.
// This runs postgres --single to complete crash recovery, then exits cleanly.
func runCrashRecovery(ctx context.Context, logger *slog.Logger) error {
	r := retry.New(constants.CrashRecoveryRetryDelay, constants.CrashRecoveryRetryDelay)
	return withRecoverySignalsDisabled(pgctld.PostgresDataDir(), logger, func() error {
		return runCrashRecoveryAttempts(ctx, logger, runSingleUserPostgres, r)
	})
}

// runCrashRecoveryAttempts retries `postgres --single` while the lock file is held.
// During the orphan-cleanup window after a postmaster crash, the lock will eventually
// release; if it does not within the retry window, postgres is genuinely running and
// we preserve the historical no-op behavior. Extracted for unit-test injection.
func runCrashRecoveryAttempts(
	ctx context.Context,
	logger *slog.Logger,
	run func(context.Context) ([]byte, error),
	r *retry.Retry,
) error {
	logger.InfoContext(ctx, "Starting single-user crash recovery")

	var lastOutput string
	for attempt, rerr := range r.Attempts(ctx) {
		if rerr != nil {
			return rerr
		}

		output, err := run(ctx)
		if err == nil {
			return nil
		}

		outputStr := string(output)
		lastOutput = outputStr

		if !postgresAlreadyRunningPattern.MatchString(outputStr) {
			logger.WarnContext(ctx, "Single-user crash recovery failed",
				"error", err,
				"output", outputStr)
			return fmt.Errorf("crash recovery failed: %w", err)
		}

		if attempt >= constants.CrashRecoveryMaxAttempts {
			break
		}

		logger.InfoContext(ctx, "Single-user crash recovery: lock file held, retrying",
			"attempt", attempt,
			"max_attempts", constants.CrashRecoveryMaxAttempts,
			"output", outputStr)
	}

	logger.InfoContext(ctx, "Single-user crash recovery not needed, postgres is already running",
		"attempts", constants.CrashRecoveryMaxAttempts,
		"output", lastOutput)
	return nil
}

// runSingleUserPostgres runs `postgres --single` once and returns its combined
// output and exit error. /dev/null on stdin causes single-user mode to perform
// recovery and exit on EOF.
func runSingleUserPostgres(ctx context.Context) ([]byte, error) {
	cmd := executil.Command(ctx, "postgres", "--single", "-D", pgctld.PostgresDataDir(), "template1")

	devNull, err := os.Open("/dev/null")
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/null: %w", err)
	}
	defer devNull.Close()

	cmd.SetStdin(devNull)
	return cmd.CombinedOutput()
}

// For primary-replacement lifecycle testing, an old primary can need crash
// recovery before pg_rewind, while standby.signal from a failed restart prevents
// postgres --single from starting. Hide the signal files only for the single-user
// crash-recovery attempt, then restore them before normal startup.
func withRecoverySignalsDisabled(dataDir string, logger *slog.Logger, fn func() error) error {
	restores := make([]func() error, 0, 2)
	for _, name := range []string{"standby.signal", "recovery.signal"} {
		restore, err := moveSignalAside(dataDir, name, logger)
		if err != nil {
			if restoreErr := restoreRecoverySignals(restores); restoreErr != nil {
				return errors.Join(err, restoreErr)
			}
			return err
		}
		if restore != nil {
			restores = append(restores, restore)
		}
	}

	runErr := fn()
	if restoreErr := restoreRecoverySignals(restores); restoreErr != nil {
		if runErr != nil {
			return errors.Join(runErr, restoreErr)
		}
		return restoreErr
	}
	return runErr
}

func restoreRecoverySignals(restores []func() error) error {
	var restoreErrs []error
	for i := len(restores) - 1; i >= 0; i-- {
		if err := restores[i](); err != nil {
			restoreErrs = append(restoreErrs, err)
		}
	}
	if len(restoreErrs) > 0 {
		return errors.Join(restoreErrs...)
	}
	return nil
}

func moveSignalAside(dataDir, name string, logger *slog.Logger) (func() error, error) {
	path := filepath.Join(dataDir, name)
	disabledPath := path + ".crash-recovery-disabled"

	if _, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to stat %s: %w", path, err)
		}
		if _, disabledErr := os.Stat(disabledPath); disabledErr != nil {
			if os.IsNotExist(disabledErr) {
				return nil, nil
			}
			return nil, fmt.Errorf("failed to stat disabled signal %s: %w", disabledPath, disabledErr)
		}
		logger.Warn("Found recovery signal already disabled before crash recovery; will restore after attempt",
			"signal", name,
			"path", path,
			"disabled_path", disabledPath)
		return restoreRecoverySignal(path, disabledPath, name, logger), nil
	}

	if err := os.Remove(disabledPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to remove stale disabled signal %s: %w", disabledPath, err)
	}
	if err := os.Rename(path, disabledPath); err != nil {
		return nil, fmt.Errorf("failed to move %s aside for crash recovery: %w", path, err)
	}
	logger.Info("Temporarily disabled PostgreSQL recovery signal for crash recovery",
		"signal", name,
		"path", path)

	return restoreRecoverySignal(path, disabledPath, name, logger), nil
}

func restoreRecoverySignal(path, disabledPath, name string, logger *slog.Logger) func() error {
	return func() error {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("cannot restore %s: file already exists", path)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("failed to stat %s before restore: %w", path, err)
		}
		if err := os.Rename(disabledPath, path); err != nil {
			return fmt.Errorf("failed to restore %s after crash recovery: %w", path, err)
		}
		logger.Info("Restored PostgreSQL recovery signal after crash recovery",
			"signal", name,
			"path", path)
		return nil
	}
}
