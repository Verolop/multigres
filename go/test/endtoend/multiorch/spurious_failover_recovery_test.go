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

package multiorch

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	commonconsensus "github.com/multigres/multigres/go/common/consensus"
	clustermetadatapb "github.com/multigres/multigres/go/pb/clustermetadata"
	consensuspb "github.com/multigres/multigres/go/pb/consensus"
	consensusdatapb "github.com/multigres/multigres/go/pb/consensusdata"
	"github.com/multigres/multigres/go/test/endtoend/shardsetup"
	"github.com/multigres/multigres/go/test/utils"
)

func TestSpuriousFailoverRecoveryWithSparePooler(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping spurious failover recovery test in short mode")
	}
	if utils.ShouldSkipRealPostgres() {
		t.Skip("Skipping end-to-end spurious failover recovery test (no postgres binaries)")
	}

	setup, cleanup := shardsetup.NewIsolated(t,
		shardsetup.WithMultipoolerCount(3),
		shardsetup.WithMultiOrchCount(1),
		shardsetup.WithDatabase("postgres"),
		shardsetup.WithCellName("test-cell"),
		shardsetup.WithDurabilityPolicy("AT_LEAST_2"),
		shardsetup.WithUseNewConsensusFlow(),
		shardsetup.WithMultigateway(),
	)
	defer cleanup()

	setup.StartMultiOrchs(t.Context(), t)

	primaryName := waitForShardReady(t, setup, 2 /* expectedStandbyCount */, 60*time.Second)
	t.Logf("Bootstrap complete; primary=%s", primaryName)

	resumeRecovery := setup.DisableRecovery(t, "multiorch")

	type poolerClient struct {
		name      string
		consensus consensuspb.MultiPoolerConsensusClient
	}
	poolerClients := make([]*poolerClient, 0, len(setup.Multipoolers))
	for name, inst := range setup.Multipoolers {
		conn, err := grpc.NewClient(
			fmt.Sprintf("localhost:%d", inst.Multipooler.GrpcPort),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err, "dial multipooler %s", name)
		t.Cleanup(func() { _ = conn.Close() })
		poolerClients = append(poolerClients, &poolerClient{
			name:      name,
			consensus: consensuspb.NewMultiPoolerConsensusClient(conn),
		})
	}

	statuses := make([]*clustermetadatapb.ConsensusStatus, 0, len(poolerClients))
	for _, pc := range poolerClients {
		resp, err := pc.consensus.Status(utils.WithShortDeadline(t), &consensusdatapb.StatusRequest{})
		require.NoError(t, err, "Status on %s", pc.name)
		require.NotNil(t, resp.GetConsensusStatus(), "ConsensusStatus from %s", pc.name)
		statuses = append(statuses, resp.GetConsensusStatus())
	}

	testCoordinatorID := &clustermetadatapb.ID{
		Component: clustermetadatapb.ID_MULTIORCH,
		Cell:      "test-cell",
		Name:      "test-coordinator",
	}
	revocation, err := commonconsensus.NewTermRevocation(statuses, testCoordinatorID)
	require.NoError(t, err, "build term revocation")
	t.Logf("Recruiting all poolers at new term: %d", revocation.GetRevokedBelowTerm())

	type recruitResult struct {
		name string
		err  error
	}
	recruitCh := make(chan recruitResult, len(poolerClients))
	for _, pc := range poolerClients {
		go func(pc *poolerClient) {
			_, callErr := pc.consensus.Recruit(utils.WithTimeout(t, 30*time.Second), &consensusdatapb.RecruitRequest{
				TermRevocation: revocation,
			})
			recruitCh <- recruitResult{name: pc.name, err: callErr}
		}(pc)
	}
	for range poolerClients {
		r := <-recruitCh
		require.NoError(t, r.err, "Recruit on %s", r.name)
	}
	t.Logf("Recruit complete at term %d; handing recovery back to multiorch", revocation.GetRevokedBelowTerm())

	resumeRecovery()
	setup.RequireRecovery(t, "multiorch", 90*time.Second)
}
