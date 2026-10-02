package correlate

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
)

// referenceEvents computes the expected event partition directly from the
// definition: within each correlation partition, enumerate every alert
// triple whose time span is <= Window, union co-members, and keep components
// of size >= 3. O(n^3); only for small test inputs.
func referenceEvents(alerts []Alert) map[string]map[string]EventSummary {
	type pkey struct {
		tenant, endpoint, corr string
	}
	byPart := map[pkey][]Alert{}
	for _, a := range alerts {
		k := pkey{a.TenantID, a.EndpointID, a.CorrelationKey}
		byPart[k] = append(byPart[k], a)
	}
	out := map[string]map[string]EventSummary{}
	for _, alerts := range byPart {
		n := len(alerts)
		parent := make([]int, n)
		for i := range parent {
			parent[i] = i
		}
		var find func(int) int
		find = func(x int) int {
			if parent[x] != x {
				parent[x] = find(parent[x])
			}
			return parent[x]
		}
		union := func(a, b int) {
			ra, rb := find(a), find(b)
			if ra != rb {
				parent[ra] = rb
			}
		}
		for i := 0; i < n; i++ {
			for j := i + 1; j < n; j++ {
				for k := j + 1; k < n; k++ {
					lo := min3(alerts[i].OccurredAt, alerts[j].OccurredAt, alerts[k].OccurredAt)
					hi := max3(alerts[i].OccurredAt, alerts[j].OccurredAt, alerts[k].OccurredAt)
					if hi-lo <= Window {
						union(i, j)
						union(j, k)
					}
				}
			}
		}
		groups := map[int][]int{}
		for i := 0; i < n; i++ {
			groups[find(i)] = append(groups[find(i)], i)
		}
		for _, members := range groups {
			if len(members) < 3 {
				continue
			}
			sum := EventSummary{EventID: alerts[members[0]].AlertID, MinTime: alerts[members[0]].OccurredAt, MaxTime: alerts[members[0]].OccurredAt}
			for _, m := range members {
				a := alerts[m]
				if a.AlertID < sum.EventID {
					sum.EventID = a.AlertID
				}
				if a.OccurredAt < sum.MinTime {
					sum.MinTime = a.OccurredAt
				}
				if a.OccurredAt > sum.MaxTime {
					sum.MaxTime = a.OccurredAt
				}
				sum.Count++
			}
			for _, m := range members {
				a := alerts[m]
				if out[a.TenantID] == nil {
					out[a.TenantID] = map[string]EventSummary{}
				}
				out[a.TenantID][a.AlertID] = sum
			}
		}
	}
	return out
}

func min3(a, b, c int64) int64 {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}

func max3(a, b, c int64) int64 {
	if b > a {
		a = b
	}
	if c > a {
		a = c
	}
	return a
}

// TestAgainstReference feeds small random workloads (duplicates, identical
// timestamps, cross-partition alerts, Window-boundary times) and, after
// every insert prefix, compares Locate and Members against the reference.
func TestAgainstReference(t *testing.T) {
	rng := rand.New(rand.NewSource(20261003))
	tenants := []string{"t1", "t2"}
	endpoints := []string{"e1", "e2"}
	keys := []string{"k1", "k2"}
	// Time pool concentrates around 0, Window and 2*Window so boundary
	// spans (exactly 600000ms) and same-timestamp alerts occur often.
	timePool := []int64{0, 1, 1000, Window - 1, Window, Window + 1, 2 * Window, 2*Window + 1, 300000, 900000}

	for trial := 0; trial < 200; trial++ {
		n := 4 + rng.Intn(14)
		var alerts []Alert
		for i := 0; i < n; i++ {
			a := Alert{
				TenantID:       tenants[rng.Intn(len(tenants))],
				EndpointID:     endpoints[rng.Intn(len(endpoints))],
				CorrelationKey: keys[rng.Intn(len(keys))],
				AlertID:        fmt.Sprintf("id-%d", rng.Intn(10)), // colliding IDs across tenants are fine
				OccurredAt:     timePool[rng.Intn(len(timePool))],
			}
			alerts = append(alerts, a)
		}
		// Sprinkle duplicate deliveries (identical content guaranteed).
		for i := 0; i < n/3; i++ {
			alerts = append(alerts, alerts[rng.Intn(n)])
		}
		rng.Shuffle(len(alerts), func(i, j int) { alerts[i], alerts[j] = alerts[j], alerts[i] })

		c := New()
		seen := map[string]map[string]bool{} // tenant -> alertID -> delivered
		var unique []Alert
		for step, a := range alerts {
			c.Add(a)
			if seen[a.TenantID] == nil {
				seen[a.TenantID] = map[string]bool{}
			}
			if !seen[a.TenantID][a.AlertID] {
				seen[a.TenantID][a.AlertID] = true
				unique = append(unique, a)
			}

			want := referenceEvents(unique)
			for tenant, ids := range seen {
				for id := range ids {
					gotSum, gotOK := c.Locate(tenant, id)
					wantSum, wantOK := want[tenant][id]
					if gotOK != wantOK {
						t.Fatalf("trial %d step %d: Locate(%s,%s) ok=%v, want ok=%v", trial, step, tenant, id, gotOK, wantOK)
					}
					if gotOK && gotSum != wantSum {
						t.Fatalf("trial %d step %d: Locate(%s,%s) = %+v, want %+v", trial, step, tenant, id, gotSum, wantSum)
					}
					gotMembers := c.Members(tenant, id)
					if !wantOK {
						if gotMembers != nil {
							t.Fatalf("trial %d step %d: Members(%s,%s) non-empty for non-event alert", trial, step, tenant, id)
						}
						continue
					}
					if len(gotMembers) != wantSum.Count {
						t.Fatalf("trial %d step %d: Members(%s,%s) len=%d, want %d", trial, step, tenant, id, len(gotMembers), wantSum.Count)
					}
					if !sort.SliceIsSorted(gotMembers, func(i, j int) bool {
						if gotMembers[i].OccurredAt != gotMembers[j].OccurredAt {
							return gotMembers[i].OccurredAt < gotMembers[j].OccurredAt
						}
						return gotMembers[i].AlertID < gotMembers[j].AlertID
					}) {
						t.Fatalf("trial %d step %d: Members(%s,%s) not sorted", trial, step, tenant, id)
					}
				}
			}
			// Unknown alerts must report no event.
			if _, ok := c.Locate("no-such-tenant", "no-such-id"); ok {
				t.Fatalf("trial %d step %d: unknown alert reported in event", trial, step)
			}
			if m := c.Members("no-such-tenant", "no-such-id"); m != nil {
				t.Fatalf("trial %d step %d: unknown alert has members", trial, step)
			}
		}
	}
}

// TestDuplicateDoesNotChangeCount checks idempotent redelivery explicitly.
func TestDuplicateDoesNotChangeCount(t *testing.T) {
	c := New()
	a := makeAlert("dup-1", 0)
	c.Add(a)
	c.Add(makeAlert("dup-2", 1000))
	c.Add(makeAlert("dup-3", 2000))
	sum, ok := c.Add(a) // duplicate of first
	if !ok || sum.Count != 3 {
		t.Fatalf("after duplicate: %+v ok=%v, want count 3", sum, ok)
	}
	if m := c.Members("tenant-1", "dup-1"); len(m) != 3 {
		t.Fatalf("members len = %d, want 3", len(m))
	}
}
