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

package poolserver

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// AllocLease allocates a port for a unique acquisition identity. The lease is
// retained on disconnect: connection loss does not prove that its user exited.
// An ambiguous reply must quarantine the owner, not retry with a new identity.
func (c *Client) AllocLease(id string) (int, error) {
	response, err := c.send("LEASE " + id)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(response)
	if len(fields) != 3 || fields[0] != "LEASE" || fields[2] != id {
		return 0, fmt.Errorf("lease %s: unexpected response %q", id, response)
	}
	port, err := strconv.Atoi(fields[1])
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid lease port %q", fields[1])
	}
	return port, nil
}

// ReleaseLease is safe to repeat after a lost acknowledgement, even if the port
// has been reassigned. Only the exact acquisition identity can release it.
func (c *Client) ReleaseLease(port int, id string) error {
	response, err := c.send(fmt.Sprintf("RELEASE %d %s", port, id))
	if err != nil {
		return err
	}
	if response != respOK {
		return fmt.Errorf("release lease %s: %s", id, response)
	}
	return nil
}

func (s *Server) handleLease(fields []string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if fields[0] == "RELEASE" {
		if len(fields) != 3 {
			return "ERR invalid release"
		}
		port, err := strconv.Atoi(fields[1])
		if err != nil {
			return "ERR invalid port"
		}
		held, exists := s.leaseIDs[fields[2]]
		if !exists {
			return "ERR unknown lease"
		}
		if held == 0 {
			return respOK
		}
		if held != port || s.leases[port] != fields[2] {
			return "ERR lease mismatch"
		}
		delete(s.allocated, port)
		delete(s.leases, port)
		s.leaseIDs[fields[2]] = 0
		return respOK
	}
	if len(fields) != 2 || len(fields[1]) < 16 || len(fields[1]) > 128 {
		return "ERR invalid lease identity"
	}
	id := fields[1]
	if port, exists := s.leaseIDs[id]; exists {
		if port == 0 {
			return "ERR lease already released"
		}
		return fmt.Sprintf("LEASE %d %s", port, id)
	}
	// Hold collisions open until allocation finishes, bounding retries without
	// accidentally choosing a port already reserved by either protocol.
	var held []net.Listener
	defer func() {
		for _, l := range held {
			_ = l.Close()
		}
	}()
	for range maxAllocRetries {
		l, err := s.listenPort()
		if err != nil {
			return "ERR " + err.Error()
		}
		held = append(held, l)
		port := l.Addr().(*net.TCPAddr).Port
		if _, exists := s.allocated[port]; exists {
			continue
		}
		s.allocated[port] = struct{}{}
		s.leases[port] = id
		s.leaseIDs[id] = port
		return fmt.Sprintf("LEASE %d %s", port, id)
	}
	return respErrCollision
}
