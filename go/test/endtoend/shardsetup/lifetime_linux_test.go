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

package shardsetup

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/multigres/multigres/go/test/utils/poolserver"
	"github.com/stretchr/testify/require"
)

func TestLifetimeConstructorUnwind(t *testing.T) {
	if os.Getenv("MULTIGRES_DISPOSABLE_LINUX") != "1" {
		t.Skip("requires a new disposable Linux worker")
	}
	dir := t.TempDir()
	server, err := poolserver.NewServer(filepath.Join(dir, "pool.sock"))
	require.NoError(t, err)
	serverDone := make(chan struct{})
	go func() { defer close(serverDone); server.Serve() }()
	defer func() { server.Stop(); <-serverDone }()
	b, err := NewLifetime(t.Context(), server.SocketPath())
	require.NoError(t, err)
	defer func() { require.NoError(t, b.Close(t.Failed())) }()
	canary := New(t, WithLifetime(b), WithMultipoolerCount(2), WithMultigateway())
	bProcesses, err := captureOwnedProcesses(b.id, b.commands)
	require.NoError(t, err)
	defer bProcesses.close()
	checkB := func(t *testing.T) {
		for pid, proc := range bProcesses.processes {
			if !proc.direct {
				continue
			}
			_, start, err := processIdentity(pid)
			require.NoError(t, err)
			require.Equal(t, proc.start, start)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, GetTestUserDSN("localhost", canary.MultigatewayPgPort, "sslmode=disable"))
		require.NoError(t, err)
		defer conn.Close(ctx)
		var one int
		require.NoError(t, conn.QueryRow(ctx, "SELECT 1").Scan(&one))
		require.Equal(t, 1, one)

		require.NotEmpty(t, b.ports.Reservations())
	}
	checkB(t)
	for _, boundary := range []string{"before-first-child", "ports-allocated", "etcd-ready", "database-children-ready", "before-transfer"} {
		for _, canceled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/canceled=%t", boundary, canceled), func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				a, err := NewLifetime(ctx, server.SocketPath())
				require.NoError(t, err)
				entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				defer unblock()
				var identities *ownedProcesses
				releaseChecks := 0
				a.boundary = func(name string) {
					if name == "before-lease-release" {
						releaseChecks++
						if identities != nil {
							for pid, proc := range identities.processes {
								_, start, err := processIdentity(pid)
								if !os.IsNotExist(err) && start == proc.start {
									t.Errorf("port release preceded process join: %d/%s", pid, start)
								}
							}
						}
					}
					if name == boundary {
						close(entered)
						<-release
						runtime.Goexit()
					}
				}
				returned := false
				go func() { defer close(done); New(t, WithLifetime(a), WithMultipoolerCount(2)); returned = true }()
				select {
				case <-entered:
				case <-done:
					t.Fatal("constructor exited before requested boundary")
				}
				identities, err = captureOwnedProcesses(a.id, a.commands)
				require.NoError(t, err)
				defer identities.close()
				if boundary != "before-first-child" && boundary != "ports-allocated" {
					require.NotEmpty(t, identities.processes)
					require.NotEmpty(t, a.ports.Reservations())
				}
				for pid, proc := range identities.processes {
					t.Logf("A pid=%d start=%s direct=%t", pid, proc.start, proc.direct)
				}
				for pid, proc := range bProcesses.processes {
					t.Logf("B pid=%d start=%s direct=%t", pid, proc.start, proc.direct)
				}
				if canceled {
					cancel()
				}
				checkB(t)
				unblock()
				<-done
				require.False(t, returned)
				require.Equal(t, 1, releaseChecks)
				require.NoError(t, a.Close(true))
				require.NoError(t, a.Close(true))
				require.Empty(t, a.ports.Reservations(), "joined teardown must precede lease release")
				for pid, proc := range identities.processes {
					_, start, err := processIdentity(pid)
					require.True(t, os.IsNotExist(err) || start != proc.start, "A identity survived: %d/%s", pid, proc.start)
				}
				_, err = os.Stat(a.setup.TempDir)
				require.NoError(t, err, "failed constructor logs intentionally retained")
				checkB(t)
			})
		}
	}
}

// Expected testing.T failures run in a child test process so the parent can
// assert the actual Fatal/Goexit path without weakening the constructor API.
func TestLifetimeFatalConstructorUnwind(t *testing.T) {
	if os.Getenv("MULTIGRES_DISPOSABLE_LINUX") != "1" {
		t.Skip("requires a new disposable Linux worker")
	}
	for _, mode := range []string{"cancellation", "exec-start"} {
		t.Run(mode, func(t *testing.T) {
			evidence := filepath.Join(t.TempDir(), "unwind.json")
			binary, err := os.Executable()
			require.NoError(t, err)
			cmd := exec.CommandContext(t.Context(), binary, "-test.v", "-test.run=^TestLifetimeFatalHelper$", "-test.timeout=1m")
			cmd.Env = append(os.Environ(), "LIFETIME_HELPER="+mode, "LIFETIME_EVIDENCE="+evidence)
			output, err := cmd.CombinedOutput()
			require.Error(t, err, string(output))
			var exitErr *exec.ExitError
			require.ErrorAs(t, err, &exitErr)
			require.Equal(t, 1, exitErr.ExitCode(), string(output))
			if mode == "cancellation" {
				require.Contains(t, string(output), "constructor canceled at etcd-ready")
			} else {
				require.Contains(t, string(output), "failed to start etcd")
			}
			data, err := os.ReadFile(evidence)
			require.NoError(t, err, string(output))
			var status struct {
				Joined       bool
				Reservations []int
			}
			require.NoError(t, json.Unmarshal(data, &status))
			require.True(t, status.Joined, string(output))
			require.Empty(t, status.Reservations)
		})
	}
}

func TestLifetimeFatalHelper(t *testing.T) {
	mode := os.Getenv("LIFETIME_HELPER")
	if os.Getenv("MULTIGRES_DISPOSABLE_LINUX") != "1" || mode == "" {
		t.Skip("constructor failure subprocess only")
	}
	dir := t.TempDir()
	server, err := poolserver.NewServer(filepath.Join(dir, "s"))
	require.NoError(t, err)
	serverDone := make(chan struct{})
 go func(){ defer close(serverDone);server.Serve() }()
 defer func(){server.Stop();<-serverDone}()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	owner, err := NewLifetime(ctx, server.SocketPath())
	require.NoError(t, err)
	var identities *ownedProcesses
	t.Cleanup(func() {
		joined := owner.Close(true) == nil
		if identities != nil {
			defer identities.close()
			for pid, proc := range identities.processes {
				_, start, err := processIdentity(pid)
				if !os.IsNotExist(err) && start == proc.start {
					joined = false
				}
			}
		}
		data, err := json.Marshal(struct {
			Joined       bool
			Reservations []int
		}{joined, owner.ports.Reservations()})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(os.Getenv("LIFETIME_EVIDENCE"), data, 0o600))
	})
	owner.boundary = func(name string) {
		if mode == "exec-start" && name == "ports-allocated" {
			owner.commands[len(owner.commands)-1].Path = filepath.Join(dir, "missing-executable")
		}
		if mode == "cancellation" && name == "etcd-ready" {
			identities, err = captureOwnedProcesses(owner.id, owner.commands)
			require.NoError(t, err)
			canceled := make(chan struct{})
			go func() { cancel(); close(canceled) }()
			<-canceled
		}
	}
	New(t, WithLifetime(owner))
	t.Fatal("constructor unexpectedly returned")
}
