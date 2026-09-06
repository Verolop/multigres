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
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

type scopePool struct {
	mu       sync.Mutex
	held     map[int]string
	returns  int
	mode     string
	listener net.Listener
	clients  []net.Conn
	wg       sync.WaitGroup
}

func newScopePool(t *testing.T, mode string) *scopePool {
	t.Helper()
	dir, err := os.MkdirTemp("", "scope-pool-")
	require.NoError(t, err)
	listener, err := net.Listen("unix", filepath.Join(dir, "s"))
	require.NoError(t, err)
	p := &scopePool{held: map[int]string{}, mode: mode, listener: listener}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.clients = append(p.clients, c)
			p.mu.Unlock()
			p.wg.Go(func() {
				defer c.Close()
				scanner := bufio.NewScanner(c)
				for scanner.Scan() {
					f := strings.Fields(scanner.Text())
					reply := "ERR invalid"
					p.mu.Lock()
					switch f[0] {
					case "LEASE":
						port := 25001
						for p.held[port] != "" && port < 25004 {
							port++
						}
						if port == 25004 {
							reply = "ERR capacity"
						} else {
							p.held[port] = f[1]
							reply = fmt.Sprintf("LEASE %d %s", port, f[1])
						}
					case "RELEASE":
						p.returns++
						port, _ := strconv.Atoi(f[1])
						if p.mode == "rejected" {
							reply = "ERR controlled rejection"
						} else {
							if p.held[port] == f[2] {
								delete(p.held, port)
							}
							reply = "OK"
						}
						if p.mode == "lost-ack" {
							p.mu.Unlock()
							return
						}
					}
					p.mu.Unlock()
					if _, err := fmt.Fprintln(c, reply); err != nil {
						return
					}
				}
			})
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		p.mu.Lock()
		for _, c := range p.clients {
			_ = c.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
		_ = os.RemoveAll(dir)
	})
	return p
}

func (p *scopePool) scope(t *testing.T) *PortScope {
	t.Helper()
	s, err := NewPortScope(p.listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = s.Close()
		// The fake worker is now destroyed. Remove only its quarantined test entries.
		for port, id := range s.ports {
			portCache.CompareAndDelete(port, id)
		}
	})
	return s
}

func TestPortScopeSeedLifetime(t *testing.T) {
	p := newScopePool(t, "")
	b := p.scope(t)
	bp, err := b.Alloc()
	require.NoError(t, err)
	for range 12 {
		a := p.scope(t)
		ap, err := a.Alloc()
		require.NoError(t, err)
		require.NotEqual(t, bp, ap)
		require.NoError(t, a.Close())
		require.NoError(t, a.Close())
		_, held := portCache.Load(ap)
		require.False(t, held)
		p.mu.Lock()
		bHeld := p.held[bp] != ""
		p.mu.Unlock()
		require.True(t, bHeld)
	}
	require.NoError(t, b.Close())
	p.mu.Lock()
	defer p.mu.Unlock()
	require.Empty(t, p.held)
	require.Equal(t, 13, p.returns)
}

func TestPortScopeLocalLifetime(t *testing.T) {
	b, err := NewPortScope("")
	require.NoError(t, err)
	defer b.Close()
	bp, err := b.Alloc()
	require.NoError(t, err)
	for range 12 {
		a, err := NewPortScope("")
		require.NoError(t, err)
		ap, err := a.Alloc()
		require.NoError(t, err)
		require.NotEqual(t, bp, ap)
		require.NoError(t, a.Close())
		require.NoError(t, a.Close())
		_, aHeld := portCache.Load(ap)
		_, bHeld := portCache.Load(bp)
		require.False(t, aHeld)
		require.True(t, bHeld)
	}
}

func TestPortScopeFailedReleaseQuarantines(t *testing.T) {
	for _, mode := range []string{"rejected", "lost-ack", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			p := newScopePool(t, mode)
			a := p.scope(t)
			b := p.scope(t)
			ap, err := a.Alloc()
			require.NoError(t, err)
			bp, err := b.Alloc()
			require.NoError(t, err)
			if mode == "disconnect" {
				require.NoError(t, a.client.Close())
			}
			err = a.Close()
			require.Error(t, err)
			require.Equal(t, err, a.Close())
			_, aHeld := portCache.Load(ap)
			require.True(t, aHeld, "uncertainty must retain local reservation")
			p.mu.Lock()
			bHeld := p.held[bp] != ""
			p.mu.Unlock()
			require.True(t, bHeld)
			_, err = a.Alloc()
			require.Error(t, err)
		})
	}
}
