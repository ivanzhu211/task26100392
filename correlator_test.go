package correlate

import (
	"math/rand"
	"sort"
	"testing"
)

func sec(s int64) int64 { return s * 1000 }

func sixAlertTimes() []int64 {
	return []int64{sec(0), sec(60), sec(120), sec(720), sec(780), sec(840)}
}

func makeAlert(id string, t int64) Alert {
	return Alert{
		TenantID:       "tenant-1",
		EndpointID:     "endpoint-1",
		CorrelationKey: "threat-1",
		AlertID:        id,
		OccurredAt:     t,
	}
}

// addSix ingests the six alerts at 0/60/120s and 720/780/840s in the given
// order and returns the correlator with the per-time alert IDs used.
func addSix(c *Correlator, order []int) map[int64]string {
	ids := map[int64]string{}
	for _, t := range sixAlertTimes() {
		ids[t] = "a-" + itoa(t)
	}
	for _, i := range order {
		c.Add(makeAlert(ids[sixAlertTimes()[i]], sixAlertTimes()[i]))
	}
	return ids
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// TestTwoEventsThenMerge covers the required scenario: alerts at 0/60/120s
// and 720/780/840s form two separate events; a late alert at 420s bridges
// them (120s..720s spans exactly 600000ms) and old members must immediately
// point at the merged event.
func TestTwoEventsThenMerge(t *testing.T) {
	c := New()
	ids := addSix(c, []int{0, 1, 2, 3, 4, 5})
	times := sixAlertTimes()

	first := []int64{times[0], times[1], times[2]}
	second := []int64{times[3], times[4], times[5]}

	sum1, ok := c.Locate("tenant-1", ids[times[0]])
	if !ok || sum1.Count != 3 || sum1.MinTime != times[0] || sum1.MaxTime != times[2] {
		t.Fatalf("first event summary = %+v, ok=%v", sum1, ok)
	}
	sum2, ok := c.Locate("tenant-1", ids[times[3]])
	if !ok || sum2.Count != 3 || sum2.MinTime != times[3] || sum2.MaxTime != times[5] {
		t.Fatalf("second event summary = %+v, ok=%v", sum2, ok)
	}
	if sum1.EventID == sum2.EventID {
		t.Fatalf("expected two distinct events, both = %q", sum1.EventID)
	}
	for _, tm := range first {
		if s, _ := c.Locate("tenant-1", ids[tm]); s.EventID != sum1.EventID {
			t.Fatalf("member at %d not in first event", tm)
		}
	}
	for _, tm := range second {
		if s, _ := c.Locate("tenant-1", ids[tm]); s.EventID != sum2.EventID {
			t.Fatalf("member at %d not in second event", tm)
		}
	}

	// Late alert at 420s: 120s..720s = 600000ms <= Window, bridging both.
	bridgeID := "a-bridge"
	sum, ok := c.Add(makeAlert(bridgeID, sec(420)))
	if !ok || sum.Count != 7 {
		t.Fatalf("after bridge: summary = %+v, ok=%v, want count 7", sum, ok)
	}
	if sum.MinTime != times[0] || sum.MaxTime != times[5] {
		t.Fatalf("merged span = [%d, %d], want [%d, %d]", sum.MinTime, sum.MaxTime, times[0], times[5])
	}
	// Event ID is the lexicographically smallest member alert_id.
	wantID := ids[times[0]]
	for _, id := range ids {
		if id < wantID {
			wantID = id
		}
	}
	if bridgeID < wantID {
		wantID = bridgeID
	}
	if sum.EventID != wantID {
		t.Fatalf("event id = %q, want %q", sum.EventID, wantID)
	}
	// Historical members immediately reflect the merge.
	for _, tm := range append(append([]int64{}, first...), second...) {
		s, ok := c.Locate("tenant-1", ids[tm])
		if !ok || s.EventID != sum.EventID || s.Count != 7 {
			t.Fatalf("old member at %d: %+v ok=%v, want event %q count 7", tm, s, ok, sum.EventID)
		}
	}
	members := c.Members("tenant-1", ids[times[0]])
	if len(members) != 7 {
		t.Fatalf("members len = %d, want 7", len(members))
	}
	if !sort.SliceIsSorted(members, func(i, j int) bool {
		if members[i].OccurredAt != members[j].OccurredAt {
			return members[i].OccurredAt < members[j].OccurredAt
		}
		return members[i].AlertID < members[j].AlertID
	}) {
		t.Fatalf("members not sorted by (occurred_at, alert_id): %+v", members)
	}
	if members[0].OccurredAt != times[0] || members[6].OccurredAt != times[5] {
		t.Fatalf("members span wrong: %+v", members)
	}
}

// TestArrivalOrderInvariance shuffles the seven alerts (six plus the 420s
// bridge) and requires the final event partition and IDs to be identical.
func TestArrivalOrderInvariance(t *testing.T) {
	times := append(sixAlertTimes(), sec(420))
	ids := map[int64]string{}
	for _, tm := range times {
		ids[tm] = "a-" + itoa(tm)
	}

	want := snapshot(t, times, ids, nil)
	rng := rand.New(rand.NewSource(42))
	for trial := 0; trial < 50; trial++ {
		perm := rng.Perm(len(times))
		got := snapshot(t, times, ids, perm)
		if got != want {
			t.Fatalf("trial %d perm %v:\n got %s\nwant %s", trial, perm, got, want)
		}
	}
}

// snapshot ingests the alerts in the given permutation (nil = natural order)
// and returns a canonical string describing every alert's event membership.
func snapshot(t *testing.T, times []int64, ids map[int64]string, perm []int) string {
	t.Helper()
	c := New()
	n := len(times)
	if perm == nil {
		perm = make([]int, n)
		for i := range perm {
			perm[i] = i
		}
	}
	for _, i := range perm {
		c.Add(makeAlert(ids[times[i]], times[i]))
	}
	out := ""
	for _, tm := range times {
		sum, ok := c.Locate("tenant-1", ids[tm])
		if !ok {
			out += ids[tm] + ":none;"
			continue
		}
		out += ids[tm] + ":" + sum.EventID + ";"
	}
	return out
}
