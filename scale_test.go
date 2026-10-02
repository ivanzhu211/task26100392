package correlator

import (
	"fmt"
	"math/rand"
	"testing"
)

// chainAlerts 构造一条"告警链"：相邻间隔 300000ms，
// 任意连续三条跨度恰为 600000ms，整体构成一个事件。
func chainAlerts(tenant, endpoint, key, idPrefix string, start, count int) []Alert {
	alerts := make([]Alert, count)
	for i := 0; i < count; i++ {
		alerts[i] = Alert{
			TenantID:       tenant,
			EndpointID:     endpoint,
			CorrelationKey: key,
			AlertID:        fmt.Sprintf("%s-%06d", idPrefix, start+i),
			OccurredAt:     int64(start+i) * 300000,
		}
	}
	return alerts
}

// TestScaleReverse200k 20 万条告警按时间逆序到达，最终归并为一个事件。
// treap 优先级由告警 ID 哈希决定，与到达顺序无关，逆序不会退化为链表。
func TestScaleReverse200k(t *testing.T) {
	const n = 200000
	alerts := chainAlerts("t", "e", "k", "r", 0, n)
	c := New()
	for i := n - 1; i >= 0; i-- {
		c.Add(alerts[i])
	}
	s, ok := c.Locate("t", alerts[n/2].AlertID)
	if !ok {
		t.Fatal("中部告警应已关联")
	}
	if s.Count != n || s.First != 0 || s.Last != int64(n-1)*300000 {
		t.Fatalf("逆序归并结果错误: %+v", s)
	}
	if s.EventID != "r-000000" {
		t.Fatalf("事件 ID 应为字典序最小成员: %s", s.EventID)
	}
}

// TestScaleRandom200k 同一告警集合随机顺序到达（固定种子，可重复），
// 结果必须与逆序到达完全一致。
func TestScaleRandom200k(t *testing.T) {
	const n = 200000
	alerts := chainAlerts("t", "e", "k", "r", 0, n)
	rng := rand.New(rand.NewSource(7))
	rng.Shuffle(n, func(i, j int) { alerts[i], alerts[j] = alerts[j], alerts[i] })
	c := New()
	var last Summary
	var lastOK bool
	for _, a := range alerts {
		last, lastOK = c.Add(a)
	}
	if !lastOK || last.Count != n {
		t.Fatalf("最后一条应完成归并: %+v ok=%v", last, lastOK)
	}
	s, ok := c.Locate("t", "r-199999")
	if !ok || s.Count != n || s.First != 0 || s.Last != int64(n-1)*300000 || s.EventID != "r-000000" {
		t.Fatalf("随机顺序归并结果错误: %+v ok=%v", s, ok)
	}
}

// TestLateMergeTwoLargeEvents 两个各 10 万条的大事件，
// 被一条迟到告警桥接归并；旧成员查询立即指向归并结果。
// 归并本身只涉及 O(1) 次并查集合并与链表头尾拼接，
// 不会逐个改写旧成员，也不会整组扫描。
func TestLateMergeTwoLargeEvents(t *testing.T) {
	const half = 100000
	chainA := chainAlerts("t", "e", "k", "a", 0, half)
	lastA := int64(half-1) * 300000
	// 链 B 起点与链 A 终点相距 600000ms：无桥接时两侧间隙不链接
	// （跨间隙任取三条告警的跨度至少为 900000ms > WindowMs）。
	startB := half + 1
	chainB := chainAlerts("t", "e", "k", "b", startB, half)
	firstB := int64(startB) * 300000
	if firstB-lastA != 600000 {
		t.Fatalf("链间距构造错误: %d", firstB-lastA)
	}

	c := New()
	for _, a := range chainA {
		c.Add(a)
	}
	for _, b := range chainB {
		c.Add(b)
	}
	sa, okA := c.Locate("t", chainA[0].AlertID)
	sb, okB := c.Locate("t", chainB[0].AlertID)
	if !okA || !okB || sa.Count != half || sb.Count != half || sa.EventID == sb.EventID {
		t.Fatalf("桥接前应存在两个各 %d 条的事件: %+v %+v", half, sa, sb)
	}

	// 迟到桥接告警：落在两链正中间，使左右间隙同时链接
	// （左间隙：bridge-(A 倒数第二条)=600000ms；右间隙：B.first-A.last=600000ms）。
	bridge := Alert{
		TenantID: "t", EndpointID: "e", CorrelationKey: "k",
		AlertID: "bridge", OccurredAt: lastA + 300000,
	}
	s, ok := c.Add(bridge)
	if !ok || s.Count != 2*half+1 {
		t.Fatalf("桥接后应归并为单事件: %+v ok=%v", s, ok)
	}
	if s.EventID != "a-000000" || s.First != 0 || s.Last != firstB+int64(half-1)*300000 {
		t.Fatalf("归并摘要错误: %+v", s)
	}
	// 两侧旧成员立即指向归并结果。
	for _, id := range []string{chainA[0].AlertID, chainA[half-1].AlertID, chainB[0].AlertID, chainB[half-1].AlertID} {
		s, ok := c.Locate("t", id)
		if !ok || s.Count != 2*half+1 || s.EventID != "a-000000" {
			t.Fatalf("旧成员 %s 未立即指向归并结果: %+v ok=%v", id, s, ok)
		}
	}
	if ms := c.Members("t", "bridge"); len(ms) != 2*half+1 {
		t.Fatalf("归并后成员数错误: %d", len(ms))
	}
}
