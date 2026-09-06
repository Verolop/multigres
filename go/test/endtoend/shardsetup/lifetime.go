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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/multigres/multigres/go/test/utils"
	"github.com/multigres/multigres/go/tools/executil"
)

// Lifetime owns a single constructor attempt before its first acquisition.
// Register Close with the seed owner before invoking New. A failed Close keeps
// leases reserved and requires quarantine until the isolated worker is destroyed.
// Log retention never determines whether leases may be released.
type Lifetime struct {
	boundary func(string) // test-only constructor barrier; nil in production
	ctx      context.Context
	cancel   context.CancelFunc
	ports    *utils.PortScope
	id       string
	setup    *ShardSetup
	commands []*executil.Cmd
	once     sync.Once
	err      error
}

func NewLifetime(ctx context.Context, socket string) (*Lifetime, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ports, err := utils.NewPortScope(socket)
	if err != nil {
		return nil, err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		_ = ports.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Lifetime{ctx: ctx, cancel: cancel, ports: ports, id: hex.EncodeToString(id[:])}, nil
}

func (l *Lifetime) Context() context.Context { return l.ctx }

// WithLifetime uses explicit seed-owned leases and joined constructor unwind.
// A Lifetime is single-use and must not be shared by concurrent constructors.
func WithLifetime(l *Lifetime) SetupOption {
	return func(c *SetupConfig) { c.lifetime = l }
}

func (l *Lifetime) attach(s *ShardSetup) {
	if l.setup != nil {
		panic("shardsetup: lifetime already attached")
	}
	l.setup = s
}

func (l *Lifetime) ownCommand(cmd *executil.Cmd) {
	cmd.AddEnv("MULTIGRES_SETUP_OWNER=" + l.id)
	l.commands = append(l.commands, cmd)
}

func (s *ShardSetup) port(t *testing.T) int {
	t.Helper()
	if s.lifetime == nil {
		return utils.GetFreePort(t)
	}
	if err := s.lifetime.ctx.Err(); err != nil {
		t.Fatalf("setup canceled: %v", err)
	}
	port, err := s.lifetime.ports.Alloc()
	if err != nil {
		t.Fatalf("setup port allocation: %v", err)
	}
	return port
}

// Close is idempotent, including its error disposition. It must follow runner
// teardown, which stops monitors and clients, and precede scheduler slot release.
func (l *Lifetime) Close(failed bool) error {
	l.once.Do(func() {
		// Capture descendant identities before parents exit, including detached
		// PostgreSQL and its watchdog. Only this owner's identities may be joined.
		owned, err := captureOwnedProcesses(l.id, l.commands)
		l.err = errors.Join(l.err, err)
		if owned != nil {
			defer owned.close()
		}
		if l.setup != nil {
			l.setup.cleanupLegacy(true)
		}
		l.cancel()
		for _, cmd := range l.commands {
			if cmd.Process == nil {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, stopped := cmd.Stop(ctx)
			if !stopped {
				l.err = errors.Join(l.err, fmt.Errorf("process %d did not join", cmd.Process.Pid))
			}
			if err := cmd.JoinWatcher(ctx); err != nil {
				l.err = errors.Join(l.err, err)
			}
			cancel()
		}
		if owned != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			l.err = errors.Join(l.err, owned.join(ctx))
			cancel()
		}
		if l.err != nil {
			return
		} // Keep leases and diagnostics on ambiguous teardown.
		if l.boundary != nil {
			l.boundary("before-lease-release")
		}
		l.err = l.ports.Close()
		if l.err == nil && !failed && l.setup != nil && l.setup.TempDir != "" {
			// No PID-file-based cleanup is needed after joined teardown.
			l.err = os.RemoveAll(l.setup.TempDir)
		}
	})
	return l.err
}

func (s *ShardSetup) checkBoundary(t *testing.T, name string) {
	if s.lifetime == nil {
		return
	}
	if s.lifetime.boundary != nil {
		s.lifetime.boundary(name)
	}
	if err := s.lifetime.ctx.Err(); err != nil {
		t.Fatalf("constructor canceled at %s: %v", name, err)
	}
}
