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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/multigres/multigres/go/tools/executil"
	"golang.org/x/sys/unix"
)

type ownedProcess struct {
	pid, fd int
	start   string
	direct  bool
}
type ownedProcesses struct {
	id        string
	processes map[int]ownedProcess
}

func processIdentity(pid int) (parent int, start string, err error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, "", err
	}
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return 0, "", errors.New("invalid process stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 20 {
		return 0, "", errors.New("short process stat")
	}
	parent, err = strconv.Atoi(fields[1])
	return parent, fields[19], err
}

func captureOwnedProcesses(id string, commands []*executil.Cmd) (*ownedProcesses, error) {
	p := &ownedProcesses{id: id, processes: make(map[int]ownedProcess)}
	for _, cmd := range commands {
		if cmd.Process == nil || cmd.Exited() {
			continue
		}
		if err := p.add(cmd.Process.Pid, true); err != nil {
			p.close()
			return nil, err
		}
	}
	if err := p.scan(); err != nil {
		p.close()
		return nil, err
	}
	return p, nil
}

func (p *ownedProcesses) add(pid int, direct bool) error {
	_, start, err := processIdentity(pid)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if old, ok := p.processes[pid]; ok {
		if old.start == start {
			return nil
		}
		_ = unix.Close(old.fd)
		delete(p.processes, pid)
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("pidfd for %d: %w", pid, err)
	}
	_, current, err := processIdentity(pid)
	if os.IsNotExist(err) {
		_ = unix.Close(fd)
		return nil
	}
	if err != nil {
		_ = unix.Close(fd)
		return err
	}
	if current != start {
		_ = unix.Close(fd)
		return nil
	}
	p.processes[pid] = ownedProcess{pid: pid, fd: fd, start: start, direct: direct}
	return nil
}

func (p *ownedProcesses) scan() error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	marker := []byte("MULTIGRES_SETUP_OWNER=" + p.id)
	parents := make(map[int]int)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		parent, _, err := processIdentity(pid)
		if err != nil {
			continue
		}
		parents[pid] = parent
		env, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		if err != nil {
			continue
		} // Other users' processes are outside this owner.
		for _, kv := range bytes.Split(env, []byte{0}) {
			if bytes.Equal(kv, marker) {
				if err := p.add(pid, false); err != nil {
					return err
				}
				break
			}
		}
	}
	// Zombies may have an empty environment; retain identities descended from
	// known parents before those parents exit and PID 1 adopts them.
	for changed := true; changed; {
		changed = false
		for pid, parent := range parents {
			if _, known := p.processes[pid]; known {
				continue
			}
			ancestor, owned := p.processes[parent]
			if !owned {
				continue
			}
			_, current, err := processIdentity(parent)
			if err != nil || current != ancestor.start {
				continue
			}
			if err := p.add(pid, false); err != nil {
				return err
			}
			if _, added := p.processes[pid]; added {
				changed = true
			}
		}
	}
	return nil
}

func (p *ownedProcesses) join(ctx context.Context) error {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	killAt := time.Now().Add(2 * time.Second)
	for {
		if err := p.scan(); err != nil {
			return err
		}
		alive := 0
		for pid, proc := range p.processes {
			_, current, err := processIdentity(pid)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return err
			}
			if current != proc.start {
				continue
			}
			alive++
			signal := unix.SIGTERM
			if !time.Now().Before(killAt) {
				signal = unix.SIGKILL
			}
			// pidfd binds the signal to the recorded process, never a reused PID.
			if err := unix.PidfdSendSignal(proc.fd, signal, nil, 0); err != nil {
				if errors.Is(err, unix.ESRCH) {
					continue
				}
				return err
			}
			if !proc.direct {
				// Reap only this exact descendant if it was adopted by this process.
				// Otherwise the disposable worker's init owns the reap.
				var status unix.WaitStatus
				_, _ = unix.Wait4(pid, &status, unix.WNOHANG, nil)
			}
		}
		if alive == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%d owned process identities remain: %w", alive, ctx.Err())
		case <-tick.C:
		}
	}
}

func (p *ownedProcesses) close() {
	for _, proc := range p.processes {
		_ = unix.Close(proc.fd)
	}
}
