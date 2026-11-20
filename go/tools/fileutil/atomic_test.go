// Copyright 2026 Supabase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteFileReplacesExistingMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("create existing file: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("set existing file mode: %v", err)
	}

	if err := AtomicWriteFile(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("AtomicWriteFile() error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat replaced file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600", got)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replaced file: %v", err)
	}
	if got := string(content); got != "new" {
		t.Errorf("content = %q, want %q", got, "new")
	}
}

func TestAtomicWriteFileReportsDirectorySyncFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "promises")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("create existing file: %v", err)
	}
	// Write and search permission allow replacement, but opening the directory
	// for syncing requires read permission. The new content is visible even
	// though AtomicWriteFile cannot confirm its durability.
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatalf("set directory permissions: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Errorf("restore directory permissions: %v", err)
		}
	})
	if err := AtomicWriteFile(path, []byte("new"), 0o600); !errors.Is(err, os.ErrPermission) {
		t.Errorf("AtomicWriteFile() error = %v, want permission error", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replaced file: %v", err)
	}
	if got := string(content); got != "new" {
		t.Errorf("content = %q, want new content despite sync failure", got)
	}
}
