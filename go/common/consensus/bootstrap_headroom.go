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

	clustermetadatapb "github.com/multigres/multigres/go/pb/clustermetadata"
)

// CheckInitialCohortHeadroom verifies that a bootstrap cohort both satisfies
// the durability policy and has one spare member for recovery. Without spare
// headroom, a later failover can require every committed member and wedge if
// the initial primary is recruited or excluded during recovery.
func CheckInitialCohortHeadroom(policyProto *clustermetadatapb.DurabilityPolicy, proposedCohort []*clustermetadatapb.ID) error {
	policy, err := NewPolicyFromProto(policyProto)
	if err != nil {
		return err
	}
	if err := policy.CheckAchievable(proposedCohort); err != nil {
		return err
	}

	required := int(policyProto.GetRequiredCount()) + 1
	if len(proposedCohort) < required {
		return fmt.Errorf("initial cohort requires at least one spare pooler: proposed cohort has %d poolers, required %d for %s",
			len(proposedCohort), required, policy.Description())
	}
	return nil
}
