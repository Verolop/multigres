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

package consensus

import (
	"fmt"

	"github.com/multigres/multigres/go/common/topoclient"
	clustermetadatapb "github.com/multigres/multigres/go/pb/clustermetadata"
)

// For bootstrap-to-failover lifecycle testing, do not commit a zero-spare
// initial cohort. Otherwise the first failover can fail outgoing quorum before
// exercising the recovery logic under test.
func CheckInitialCohortHeadroom(policyProto *clustermetadatapb.DurabilityPolicy, proposedCohort []*clustermetadatapb.ID) error {
	policy, err := NewPolicyFromProto(policyProto)
	if err != nil {
		return err
	}
	if err := policy.CheckAchievable(proposedCohort); err != nil {
		return err
	}

	for i, failed := range proposedCohort {
		remaining := make([]*clustermetadatapb.ID, 0, len(proposedCohort)-1)
		remaining = append(remaining, proposedCohort[:i]...)
		remaining = append(remaining, proposedCohort[i+1:]...)
		if err := policy.CheckAchievable(remaining); err != nil {
			return fmt.Errorf("initial cohort requires one-failure headroom for %s: removing %s leaves %d poolers that cannot satisfy policy: %w",
				policy.Description(), topoclient.ClusterIDString(failed), len(remaining), err)
		}
	}
	return nil
}
