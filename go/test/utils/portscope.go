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

package utils

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/multigres/multigres/go/test/utils/poolserver"
)

// PortScope owns explicit leases, independent of testing.T cleanup. Close must
// only be called after every process using its ports has exited and joined.
// Failed or ambiguous operations quarantine the scope until worker destruction.
// A configured but unavailable server never silently falls back to local ports.
type PortScope struct {
	mu     sync.Mutex
	client *poolserver.Client
	ports  map[int]string
	closed bool
	err    error
}

func NewPortScope(socket string) (*PortScope, error) {
	s := &PortScope{ports: make(map[int]string)}
	if socket != "" {
		c, err := poolserver.Connect(socket)
		if err != nil {
			return nil, err
		}
		s.client = c
	}
	return s, nil
}

func (s *PortScope) Alloc() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.err != nil {
		return 0, fmt.Errorf("port scope closed or quarantined: %w", errors.Join(s.err, errors.New("allocation unavailable")))
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return 0, err
	}
	id := hex.EncodeToString(token[:])
	if s.client != nil {
		port, err := s.client.AllocLease(id)
		if err != nil {
			s.err = err
			return 0, err
		}
		if _, exists := portCache.LoadOrStore(port, id); exists {
			s.err = fmt.Errorf("pool returned locally reserved port %d", port)
			return 0, s.err
		}
		s.ports[port] = id
		return port, nil
	}
	var held []net.Listener
	defer func() {
		for _, l := range held {
			_ = l.Close()
		}
	}()
	for {
		l, err := net.Listen("tcp", "localhost:0")
		if err != nil {
			return 0, err
		}
		held = append(held, l)
		port := l.Addr().(*net.TCPAddr).Port
		if _, exists := portCache.LoadOrStore(port, id); exists {
			continue
		}
		s.ports[port] = id
		return port, nil
	}
}

// Close returns the same status on every call. On uncertainty, the local cache
// and server lease are left reserved; no integer-only RETURN or reconnect occurs.
func (s *PortScope) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.err
	}
	s.closed = true
	if s.err == nil {
		for port, id := range s.ports {
			if s.client != nil {
				if err := s.client.ReleaseLease(port, id); err != nil {
					s.err = errors.Join(s.err, fmt.Errorf("port %d quarantined: %w", port, err))
					continue
				}
			}
			portCache.CompareAndDelete(port, id)
			delete(s.ports, port)
		}
	}
	if s.client != nil {
		s.err = errors.Join(s.err, s.client.Close())
	}
	return s.err
}

// Reservations returns ports still owned or quarantined by this scope.
func (s *PortScope) Reservations() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	ports := make([]int, 0, len(s.ports))
	for port := range s.ports {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}
