package correlate

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

const scaleN = 200000

// scaleAlert builds alert i of a single-partition workload with 10ms spacing.
func scaleAlert(i int) Alert {
	return Alert{
		TenantID:       "t",
		EndpointID:     "e",
		CorrelationKey: "k",
		AlertID:        fmt.Sprintf("alert-%06d", i),
		OccurredAt:     int64(i) * 10,
	}
}

// snapshotAll returns the event ID of every alert, in alert-ID order.
func snapshotAll(c *Correlator, n int) []string {
	out := make([]string, n)
	for i := 0; i < n; i++ {
		sum, ok := c.Locate("t", fmt.Sprintf("alert-%06d", i))
		if !ok {
			out[i] = ""
		} else {
			out[i] = sum.EventID
		}
	}
	return out
}

// TestScaleReverseAndRandom inserts 200k alerts (10ms spacing, so the whole
// partition chains into one event) in reverse and in random order, and
// requires identical final event partitions and IDs.
func TestScaleReverseAndRandom(t *testing.T) {
	insert := func(order []int) (*Correlator, time.Duration) {
		c := New()
		start := time.Now()
		for _, i := range order {
			c.Add(scaleAlert(i))
		}
		return c, time.Since(start)
	}

	rev := make([]int, scaleN)
	for i := range rev {
		rev[i] = scaleN - 1 - i
	}
	cRev, durRev := insert(rev)

	rng := rand.New(rand.NewSource(7))
	cRand, durRand := insert(rng.Perm(scaleN))
	t.Logf("insert %d alerts: reverse %v, random %v", scaleN, durRev, durRand)

	sum, ok := cRev.Locate("t", "alert-000000")
	if !ok || sum.Count != scaleN || sum.MinTime != 0 || sum.MaxTime != int64(scaleN-1)*10 {
		t.Fatalf("reverse: summary = %+v ok=%v, want one event of %d", sum, ok, scaleN)
	}
	if sum.EventID != "alert-000000" {
		t.Fatalf("event id = %q, want alert-000000", sum.EventID)
	}

	gotRev := snapshotAll(cRev, scaleN)
	gotRand := snapshotAll(cRand, scaleN)
	for i := range gotRev {
		if gotRev[i] != gotRand[i] || gotRev[i] != "alert-000000" {
			t.Fatalf("alert %d: reverse=%q random=%q, want alert-000000", i, gotRev[i], gotRand[i])
		}
	}
}

// TestLateAlertMergesTwoLargeEvents builds two 100k-member events separated
// by exactly Window, then merges them with a single late bridge alert and
// checks that old members immediately reflect the merged event.
func TestLateAlertMergesTwoLargeEvents(t *testing.T) {
	const half = 100000
	const gapStart = int64(half-1) * 10 // 999990: end of cluster A
	const clusterB = gapStart + Window  // 1599990: start of cluster B
	c := New()
	for i := 0; i < half; i++ {
		c.Add(scaleAlert(i)) // times 0..999990
	}
	for i := 0; i < half; i++ {
		c.Add(Alert{
			TenantID:       "t",
			EndpointID:     "e",
			CorrelationKey: "k",
			AlertID:        fmt.Sprintf("alert-%06d", half+i),
			OccurredAt:     clusterB + int64(i)*10,
		})
	}
	sumA, okA := c.Locate("t", "alert-000000")
	sumB, okB := c.Locate("t", fmt.Sprintf("alert-%06d", half))
	if !okA || !okB || sumA.Count != half || sumB.Count != half || sumA.EventID == sumB.EventID {
		t.Fatalf("before bridge: A=%+v(%v) B=%+v(%v)", sumA, okA, sumB, okB)
	}

	// One late alert bridging the exact-Window gap: 999990..1599990 = 600000.
	start := time.Now()
	sum, ok := c.Add(Alert{
		TenantID:       "t",
		EndpointID:     "e",
		CorrelationKey: "k",
		AlertID:        "bridge",
		OccurredAt:     gapStart + Window/2,
	})
	t.Logf("bridge insert merging two %d-member events took %v", half, time.Since(start))
	if !ok || sum.Count != 2*half+1 {
		t.Fatalf("after bridge: %+v ok=%v, want count %d", sum, ok, 2*half+1)
	}
	if sum.MinTime != 0 || sum.MaxTime != clusterB+int64(half-1)*10 {
		t.Fatalf("merged span = [%d,%d]", sum.MinTime, sum.MaxTime)
	}
	// Old members of both events immediately point at the merged event.
	for _, id := range []string{"alert-000000", fmt.Sprintf("alert-%06d", half-1), fmt.Sprintf("alert-%06d", half), fmt.Sprintf("alert-%06d", 2*half-1)} {
		s, ok := c.Locate("t", id)
		if !ok || s.EventID != sum.EventID || s.Count != 2*half+1 {
			t.Fatalf("old member %s: %+v ok=%v", id, s, ok)
		}
	}
	if m := c.Members("t", "bridge"); len(m) != 2*half+1 {
		t.Fatalf("members len = %d, want %d", len(m), 2*half+1)
	}
}
