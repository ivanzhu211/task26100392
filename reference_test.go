package correlator

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
)

// refEvent 是参考实现计算出的事件。
type refEvent struct {
	id      string
	members []Alert
}

// referenceEvents 直接按定义计算事件划分：
// 枚举每个关联分区内所有时间跨度 <= WindowMs 的三元组，
// 共享告警的三元组传递闭包即事件。仅用于小规模测试核对。
func referenceEvents(alerts []Alert) map[string]refEvent {
	// 按 (TenantID, AlertID) 去重。
	type ref struct{ tenant, id string }
	seen := make(map[ref]bool)
	var uniq []Alert
	for _, a := range alerts {
		r := ref{a.TenantID, a.AlertID}
		if seen[r] {
			continue
		}
		seen[r] = true
		uniq = append(uniq, a)
	}

	// 按关联分区聚合。
	type pk struct{ tenant, endpoint, key string }
	parts := make(map[pk][]Alert)
	for _, a := range uniq {
		k := pk{a.TenantID, a.EndpointID, a.CorrelationKey}
		parts[k] = append(parts[k], a)
	}

	out := make(map[string]refEvent)
	for _, group := range parts {
		sort.Slice(group, func(i, j int) bool {
			if group[i].OccurredAt != group[j].OccurredAt {
				return group[i].OccurredAt < group[j].OccurredAt
			}
			return group[i].AlertID < group[j].AlertID
		})
		n := len(group)
		parent := make([]int, n)
		for i := range parent {
			parent[i] = i
		}
		var find func(int) int
		find = func(x int) int {
			for parent[x] != x {
				parent[x] = parent[parent[x]]
				x = parent[x]
			}
			return x
		}
		union := func(a, b int) {
			ra, rb := find(a), find(b)
			if ra != rb {
				parent[ra] = rb
			}
		}
		// 枚举全部有效三元组。
		for i := 0; i < n; i++ {
			for j := i + 1; j < n; j++ {
				for k := j + 1; k < n; k++ {
					if group[k].OccurredAt-group[i].OccurredAt <= WindowMs {
						union(i, j)
						union(j, k)
					}
				}
			}
		}
		comps := make(map[int][]Alert)
		for i := 0; i < n; i++ {
			r := find(i)
			comps[r] = append(comps[r], group[i])
		}
		for _, members := range comps {
			if len(members) < 3 {
				continue // 未进入任何有效证据组
			}
			ev := refEvent{members: members}
			ev.id = members[0].AlertID
			for _, m := range members[1:] {
				if m.AlertID < ev.id {
					ev.id = m.AlertID
				}
			}
			for _, m := range members {
				out[m.TenantID+"\x00"+m.AlertID] = ev
			}
		}
	}
	return out
}

// checkAgainstReference 将 c 的当前状态与参考结果逐告警核对。
func checkAgainstReference(t *testing.T, c *Correlator, submitted []Alert, prefix int) {
	t.Helper()
	ref := referenceEvents(submitted)
	// 去重后的全部告警。
	type aref struct{ tenant, id string }
	seen := make(map[aref]bool)
	for _, a := range submitted {
		r := aref{a.TenantID, a.AlertID}
		if seen[r] {
			continue
		}
		seen[r] = true
		ev, linked := ref[a.TenantID+"\x00"+a.AlertID]
		s, ok := c.Locate(a.TenantID, a.AlertID)
		if ok != linked {
			t.Fatalf("前缀 %d: %s 关联状态不一致 got=%v want=%v", prefix, a.AlertID, ok, linked)
		}
		if !linked {
			if ms := c.Members(a.TenantID, a.AlertID); len(ms) != 0 {
				t.Fatalf("前缀 %d: %s 未关联但 Members 非空", prefix, a.AlertID)
			}
			continue
		}
		var first, last int64
		first = ev.members[0].OccurredAt
		last = ev.members[0].OccurredAt
		for _, m := range ev.members {
			if m.OccurredAt < first {
				first = m.OccurredAt
			}
			if m.OccurredAt > last {
				last = m.OccurredAt
			}
		}
		want := Summary{EventID: ev.id, Count: len(ev.members), First: first, Last: last}
		if s != want {
			t.Fatalf("前缀 %d: %s 摘要不一致 got=%+v want=%+v", prefix, a.AlertID, s, want)
		}
		ms := c.Members(a.TenantID, a.AlertID)
		if len(ms) != len(ev.members) {
			t.Fatalf("前缀 %d: %s 成员数不一致 got=%d want=%d", prefix, a.AlertID, len(ms), len(ev.members))
		}
		for i := range ms {
			if ms[i] != ev.members[i] {
				t.Fatalf("前缀 %d: %s 成员[%d]不一致 got=%+v want=%+v", prefix, a.AlertID, i, ms[i], ev.members[i])
			}
		}
	}
}

// TestRandomAgainstReference 对小规模随机数据，在每个插入前缀上与
// 直接按定义计算的参考结果核对。覆盖重复投递、同时间告警、
// 跨分区数据及 600000ms 边界。
func TestRandomAgainstReference(t *testing.T) {
	rng := rand.New(rand.NewSource(20261003))
	tenants := []string{"t1", "t2"}
	endpoints := []string{"e1", "e2"}
	keys := []string{"k1", "k2"}

	for trial := 0; trial < 40; trial++ {
		c := New()
		var submitted []Alert
		steps := 30 + rng.Intn(30)
		for step := 0; step < steps; step++ {
			var a Alert
			// 20% 概率重复投递已有告警（内容一致）。
			if len(submitted) > 0 && rng.Intn(5) == 0 {
				a = submitted[rng.Intn(len(submitted))]
			} else {
				id := rng.Intn(40) // 小 ID 池制造同分区密集数据
				// 时间取 50000ms 的倍数，频繁命中 600000ms 边界与同时间告警。
				ts := int64(rng.Intn(28)) * 50000
				a = Alert{
					TenantID:       tenants[rng.Intn(len(tenants))],
					EndpointID:     endpoints[rng.Intn(len(endpoints))],
					CorrelationKey: keys[rng.Intn(len(keys))],
					AlertID:        fmt.Sprintf("a%03d", id),
					OccurredAt:     ts,
				}
				// 同 (tenant, id) 已存在时必须内容一致：改用唯一 ID 保证合法输入。
				dup := false
				for _, prev := range submitted {
					if prev.TenantID == a.TenantID && prev.AlertID == a.AlertID {
						dup = true
						break
					}
				}
				if dup {
					a.AlertID = fmt.Sprintf("a%03d-x%d", id, step)
				}
			}
			gotS, gotOK := c.Add(a)
			submitted = append(submitted, a)

			// 核对 Add 返回值与参考结果中该告警的归属一致。
			ref := referenceEvents(submitted)
			ev, linked := ref[a.TenantID+"\x00"+a.AlertID]
			if gotOK != linked {
				t.Fatalf("trial %d 前缀 %d: Add 返回关联状态 got=%v want=%v", trial, step+1, gotOK, linked)
			}
			if linked {
				if gotS.EventID != ev.id || gotS.Count != len(ev.members) {
					t.Fatalf("trial %d 前缀 %d: Add 返回摘要 got=%+v want id=%s count=%d",
						trial, step+1, gotS, ev.id, len(ev.members))
				}
			}
			// 全量核对当前前缀。
			checkAgainstReference(t, c, submitted, step+1)
		}
	}
}

// TestBoundary600000 精确验证 600000ms 边界包含在内。
func TestBoundary600000(t *testing.T) {
	c := New()
	mk := func(id string, ts int64) Alert {
		return Alert{TenantID: "t", EndpointID: "e", CorrelationKey: "k", AlertID: id, OccurredAt: ts}
	}
	c.Add(mk("x", 1000000))
	c.Add(mk("y", 1300000))
	if _, ok := c.Add(mk("z", 1600000)); !ok { // 跨度恰为 600000
		t.Fatal("跨度 600000ms 的三元组应构成有效证据组")
	}
	if s, _ := c.Locate("t", "x"); s.Count != 3 {
		t.Fatalf("边界三元组应关联: %+v", s)
	}
	// 跨度 600001ms 不构成证据组。
	c2 := New()
	c2.Add(mk("x", 1000000))
	c2.Add(mk("y", 1300000))
	if _, ok := c2.Add(mk("z", 1600001)); ok {
		t.Fatal("跨度 600001ms 不应构成有效证据组")
	}
}
