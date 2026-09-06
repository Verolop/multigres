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
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type fixedListener struct{ port int }

func (l fixedListener) Accept() (net.Conn, error) { return nil, errors.New("unused") }
func (l fixedListener) Close() error              { return nil }
func (l fixedListener) Addr() net.Addr            { return &net.TCPAddr{Port: l.port} }

func leaseServer(t *testing.T) (*Server, *Client) {
	t.Helper()
	dir, err := os.MkdirTemp("", "lease-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	s, err := NewServer(filepath.Join(dir, "s"))
	require.NoError(t, err)
	s.listenPort = func() (net.Listener, error) { return fixedListener{26001}, nil }
	done := make(chan struct{})
	go func() { defer close(done); s.Serve() }()
	t.Cleanup(func() { s.Stop(); <-done })
	c, err := Connect(s.SocketPath())
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return s, c
}

func TestLeaseStaleReleaseCannotReleaseNewOwner(t *testing.T) {
	_, c := leaseServer(t)
	a, err := c.AllocLease("aaaaaaaaaaaaaaaa")
	require.NoError(t, err)
	require.NoError(t, c.ReleaseLease(a, "aaaaaaaaaaaaaaaa"))
	b, err := c.AllocLease("bbbbbbbbbbbbbbbb")
	require.NoError(t, err)
	require.Equal(t, a, b)
	for range 2 {
		require.NoError(t, c.ReleaseLease(a, "aaaaaaaaaaaaaaaa"))
	}
	require.Error(t, c.ReturnPort(a), "integer-only RETURN must not affect an identity lease")
	_, err = c.AllocLease("cccccccccccccccc")
	require.Error(t, err, "C must not receive active B's number")
	require.NoError(t, c.ReleaseLease(b, "bbbbbbbbbbbbbbbb"))
}

func TestLeaseDisconnectRetainsOwnership(t *testing.T) {
	s, c := leaseServer(t)
	a, err := c.AllocLease("aaaaaaaaaaaaaaaa")
	require.NoError(t, err)
	require.NoError(t, c.Close())
	b, err := Connect(s.SocketPath())
	require.NoError(t, err)
	defer b.Close()
	// Replaying the same acquisition reconciles a lost allocation acknowledgement.
	again, err := b.AllocLease("aaaaaaaaaaaaaaaa")
	require.NoError(t, err)
	require.Equal(t, a, again)
	_, err = b.AllocLease("bbbbbbbbbbbbbbbb")
	require.Error(t, err)
	require.NoError(t, b.ReleaseLease(a, "aaaaaaaaaaaaaaaa"))
	require.NoError(t, b.ReleaseLease(a, "aaaaaaaaaaaaaaaa"), "lost release ack is safe to replay")
	_, err = b.AllocLease("bbbbbbbbbbbbbbbb")
	require.NoError(t, err)
}
