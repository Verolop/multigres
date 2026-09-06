//go:build !linux

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
	"errors"

	"github.com/multigres/multigres/go/tools/executil"
)

type ownedProcesses struct{}

func captureOwnedProcesses(_ string, commands []*executil.Cmd) (*ownedProcesses, error) {
	for _, cmd := range commands {
		if cmd.Process != nil {
			return nil, errors.New("joined setup ownership requires an isolated Linux worker")
		}
	}
	return &ownedProcesses{}, nil
}
func (*ownedProcesses) join(context.Context) error { return nil }
func (*ownedProcesses) close()                     {}
