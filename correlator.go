// Package correlator 实现 MDR 平台的告警关联组件：
// 将乱序到达的告警按归并语义实时归并为安全事件。
//
// 归并语义的结构化刻画（实现依据）：
// 将同一关联分区（TenantID, EndpointID, CorrelationKey）内的告警
// 按 (OccurredAt, AlertID) 排序。对相邻告警间隙 (a, b)，定义其“链接”
// 当且仅当存在一个有效证据组（时间跨度 <= WindowMs 的三条不同告警），
// 其最小时间 <= a.OccurredAt 且最大时间 >= b.OccurredAt。
// 可以证明该条件等价于：
//
//	(a 的前前驱存在且 b.time - prev(a).time <= WindowMs) 或
//	(b 的后后继存在且 next(b).time - a.time <= WindowMs)
//
// 即间隙的链接状态只取决于两侧各两条告警。进而：
//   - 证据组共享关系的传递闭包（安全事件）恰好是极大连续链接段；
//   - 链接段长度必 >= 3，未链接孤点即未关联告警；
//   - 插入只会使间隙由未链接变为链接，永不反向（单调性），
//     因此可以用并查集维护事件，迟到告警天然支持事件合并。
//
// 每次插入只需重估插入点前后 O(1) 个间隙，无需扫描整个分区。
package correlator

import "sort"

// WindowMs 是有效证据组允许的最大时间跨度（10 分钟，边界包含）。
const WindowMs int64 = 600000

// Alert 是一条检测规则匹配后上送的告警。
type Alert struct {
	TenantID       string
	EndpointID     string
	CorrelationKey string
	AlertID        string
	OccurredAt     int64 // 非负整数毫秒时间戳
}

// Summary 是安全事件的摘要。
type Summary struct {
	EventID string // 成员中按字节字典序最小的 AlertID
	Count   int    // 成员数
	First   int64  // 最早 OccurredAt
	Last    int64  // 最晚 OccurredAt
}

type alertRef struct {
	tenantID string
	alertID  string
}

type partKey struct {
	tenantID       string
	endpointID     string
	correlationKey string
}

// Correlator 是告警关联组件，仅支持串行调用，数据驻留内存。
type Correlator struct {
	alerts map[alertRef]*node // 租户内告警去重与定位索引
	parts  map[partKey]*treap // 每个关联分区的有序索引
}

// New 创建一个空的 Correlator。
func New() *Correlator {
	return &Correlator{
		alerts: make(map[alertRef]*node),
		parts:  make(map[partKey]*treap),
	}
}

// Add 接收一条告警，返回它当前所属事件的摘要；
// 尚未关联（未进入任何有效证据组）时 ok 为 false。
// 重复提交同 (TenantID, AlertID) 的告警不增加计数。
func (c *Correlator) Add(a Alert) (s Summary, ok bool) {
	ref := alertRef{a.TenantID, a.AlertID}
	if n, dup := c.alerts[ref]; dup {
		// 输入保证重复内容一致，直接返回当前归属。
		return summaryOf(find(n))
	}

	n := &node{alert: a, prio: hashPriority(a.TenantID, a.AlertID)}
	n.parent = n
	n.size = 1
	n.minID = a.AlertID
	n.minTime, n.maxTime = a.OccurredAt, a.OccurredAt
	n.head, n.tail = n, n
	c.alerts[ref] = n

	pk := partKey{a.TenantID, a.EndpointID, a.CorrelationKey}
	tr := c.parts[pk]
	if tr == nil {
		tr = &treap{}
		c.parts[pk] = tr
	}
	tr.insert(n)

	// 插入只会改变插入点前后 O(1) 个间隙的链接状态：
	// 新间隙 (prev, n)、(n, next)，以及因前驱/后继变化而需重估的
	// (prev(prev), prev) 与 (next, next(next))。
	for _, g := range [][2]*node{
		{prevOf(prevOf(n)), prevOf(n)},
		{prevOf(n), n},
		{n, nextOf(n)},
		{nextOf(n), nextOf(nextOf(n))},
	} {
		if g[0] != nil && g[1] != nil && gapLinked(g[0], g[1]) {
			union(g[0], g[1])
		}
	}

	return summaryOf(find(n))
}

// Locate 返回指定告警当前所属事件的摘要；尚未关联时 ok 为 false。
func (c *Correlator) Locate(tenantID, alertID string) (s Summary, ok bool) {
	n, found := c.alerts[alertRef{tenantID, alertID}]
	if !found {
		return Summary{}, false
	}
	return summaryOf(find(n))
}

// Members 返回指定告警所在事件的全部成员，
// 按 (OccurredAt, AlertID) 排序；尚未关联时返回空列表。
func (c *Correlator) Members(tenantID, alertID string) []Alert {
	n, found := c.alerts[alertRef{tenantID, alertID}]
	if !found {
		return nil
	}
	root := find(n)
	if root.size < 3 {
		return nil
	}
	out := make([]Alert, 0, root.size)
	for m := root.head; m != nil; m = m.mnext {
		out = append(out, m.alert)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OccurredAt != out[j].OccurredAt {
			return out[i].OccurredAt < out[j].OccurredAt
		}
		return out[i].AlertID < out[j].AlertID
	})
	return out
}

func prevOf(n *node) *node {
	if n == nil {
		return nil
	}
	return n.prev
}

func nextOf(n *node) *node {
	if n == nil {
		return nil
	}
	return n.next
}

// gapLinked 判定有序相邻告警 a、b（a 是 b 的前驱）之间的间隙是否链接。
// 间隙链接 <=> 存在有效证据组跨越该间隙
// <=> a 侧两条告警与 b 可成组，或 b 侧两条告警与 a 可成组。
func gapLinked(a, b *node) bool {
	if pa := a.prev; pa != nil && b.alert.OccurredAt-pa.alert.OccurredAt <= WindowMs {
		return true
	}
	if nb := b.next; nb != nil && nb.alert.OccurredAt-a.alert.OccurredAt <= WindowMs {
		return true
	}
	return false
}

// find 带路径压缩的并查集查找。
func find(n *node) *node {
	root := n
	for root.parent != root {
		root = root.parent
	}
	for n.parent != root {
		n.parent, n = root, n.parent
	}
	return root
}

// union 合并两个告警所属的集合，在根上维护事件摘要与成员链表。
// 成员链表头尾拼接为 O(1)，不会逐个改写旧成员。
func union(a, b *node) {
	ra, rb := find(a), find(b)
	if ra == rb {
		return
	}
	if ra.size < rb.size {
		ra, rb = rb, ra
	}
	rb.parent = ra
	ra.size += rb.size
	if rb.minID < ra.minID {
		ra.minID = rb.minID
	}
	if rb.minTime < ra.minTime {
		ra.minTime = rb.minTime
	}
	if rb.maxTime > ra.maxTime {
		ra.maxTime = rb.maxTime
	}
	ra.tail.mnext = rb.head
	ra.tail = rb.tail
}

// summaryOf 由并查集根节点生成事件摘要；集合大小 < 3 时未构成事件。
// （链接段长度必不小于 3，故大小为 1 的集合即未关联告警。）
func summaryOf(root *node) (Summary, bool) {
	if root.size < 3 {
		return Summary{}, false
	}
	return Summary{
		EventID: root.minID,
		Count:   root.size,
		First:   root.minTime,
		Last:    root.maxTime,
	}, true
}
