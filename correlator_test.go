package correlator

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
)

// 构造题目场景：同一分区内 0/60/120 秒与 720/780/840 秒两组告警，
// 以及 420 秒的迟到桥接告警。
func scenarioAlerts() []Alert {
	sec := int64(1000)
	times := []int64{0, 60, 120, 720, 780, 840, 420}
	alerts := make([]Alert, 0, len(times))
	for i, t := range times {
		alerts = append(alerts, Alert{
			TenantID:       "tenant-1",
			EndpointID:     "endpoint-1",
			CorrelationKey: "threat-1",
			AlertID:        fmt.Sprintf("alert-%03d", i),
			OccurredAt:     t * sec,
		})
	}
	return alerts
}

// allEvents 汇总当前所有告警的事件划分：eventID -> 排序后的成员 alertID 列表。
func allEvents(c *Correlator, alerts []Alert) map[string][]string {
	events := make(map[string][]string)
	for _, a := range alerts {
		s, ok := c.Locate(a.TenantID, a.AlertID)
		if !ok {
			continue
		}
		events[s.EventID] = append(events[s.EventID], a.AlertID)
	}
	for id := range events {
		sort.Strings(events[id])
	}
	return events
}

func equalEvents(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || len(va) != len(vb) {
			return false
		}
		for i := range va {
			if va[i] != vb[i] {
				return false
			}
		}
	}
	return true
}

func TestTwoEventsThenLateMerge(t *testing.T) {
	sec := int64(1000)
	c := New()
	alerts := scenarioAlerts()

	// 前六条：0/60/120 秒构成事件 A，720/780/840 秒构成事件 B。
	for _, a := range alerts[:6] {
		c.Add(a)
	}
	sumA, ok := c.Locate("tenant-1", "alert-000")
	if !ok {
		t.Fatal("alert-000 应已关联")
	}
	if sumA.EventID != "alert-000" || sumA.Count != 3 || sumA.First != 0 || sumA.Last != 120*sec {
		t.Fatalf("事件 A 摘要错误: %+v", sumA)
	}
	sumB, ok := c.Locate("tenant-1", "alert-003")
	if !ok {
		t.Fatal("alert-003 应已关联")
	}
	if sumB.EventID != "alert-003" || sumB.Count != 3 || sumB.First != 720*sec || sumB.Last != 840*sec {
		t.Fatalf("事件 B 摘要错误: %+v", sumB)
	}
	if sumA.EventID == sumB.EventID {
		t.Fatal("此时应存在两个不同事件")
	}

	// 420 秒迟到告警到达：(120,420,720) 跨度恰为 600000ms，两事件合并。
	sum, ok := c.Add(alerts[6])
	if !ok {
		t.Fatal("桥接告警应构成事件")
	}
	if sum.Count != 7 || sum.EventID != "alert-000" || sum.First != 0 || sum.Last != 840*sec {
		t.Fatalf("合并后摘要错误: %+v", sum)
	}

	// 旧成员查询必须立即指向归并结果。
	for _, a := range alerts {
		s, ok := c.Locate(a.TenantID, a.AlertID)
		if !ok {
			t.Fatalf("%s 应已关联", a.AlertID)
		}
		if s.EventID != "alert-000" || s.Count != 7 {
			t.Fatalf("%s 归并后摘要错误: %+v", a.AlertID, s)
		}
	}

	// Members 按 (OccurredAt, AlertID) 排序返回全部 7 条。
	members := c.Members("tenant-1", "alert-005")
	if len(members) != 7 {
		t.Fatalf("成员数错误: %d", len(members))
	}
	for i := 1; i < len(members); i++ {
		if members[i-1].OccurredAt > members[i].OccurredAt {
			t.Fatal("成员未按时间排序")
		}
	}
	if members[0].OccurredAt != 0 || members[6].OccurredAt != 840*sec {
		t.Fatalf("成员边界错误: %v ... %v", members[0].OccurredAt, members[6].OccurredAt)
	}
}

func TestArrivalOrderInvariance(t *testing.T) {
	base := scenarioAlerts()
	// 参考结果：按题目给定顺序。
	ref := New()
	for _, a := range base {
		ref.Add(a)
	}
	want := allEvents(ref, base)

	// 多种随机顺序（含完全逆序）必须得到相同事件划分与事件 ID。
	orders := [][]Alert{}
	rev := make([]Alert, len(base))
	for i, a := range base {
		rev[len(base)-1-i] = a
	}
	orders = append(orders, rev)
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 50; i++ {
		sh := make([]Alert, len(base))
		copy(sh, base)
		rng.Shuffle(len(sh), func(x, y int) { sh[x], sh[y] = sh[y], sh[x] })
		orders = append(orders, sh)
	}
	for idx, order := range orders {
		c := New()
		for _, a := range order {
			c.Add(a)
		}
		if got := allEvents(c, base); !equalEvents(got, want) {
			t.Fatalf("顺序 %d 得到不同事件划分: got %v want %v", idx, got, want)
		}
	}
}
