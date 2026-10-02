package correlator

// node 是一条告警在内存中的存储节点，同时充当：
//   - 关联分区内按 (OccurredAt, AlertID) 排序的 treap 节点；
//   - 并查集（事件归属）节点；
//   - 事件成员链表节点。
type node struct {
	alert Alert

	prio  uint64 // 由 (TenantID, AlertID) 哈希决定，与插入顺序无关
	left  *node
	right *node
	prev  *node // 有序双向链表：按 (OccurredAt, AlertID) 的前驱
	next  *node // 有序双向链表：后继

	parent *node // 并查集父指针
	size   int   // 并查集根：集合大小

	// 以下字段仅在并查集根节点上有意义：事件摘要与成员链表。
	minID   string
	minTime int64
	maxTime int64
	head    *node
	tail    *node
	mnext   *node // 事件成员链表指针
}

// less 比较两条告警在分区内的排序键 (OccurredAt, AlertID)。
func less(a, b *node) bool {
	if a.alert.OccurredAt != b.alert.OccurredAt {
		return a.alert.OccurredAt < b.alert.OccurredAt
	}
	return a.alert.AlertID < b.alert.AlertID
}

// hashPriority 生成确定性的 treap 优先级（FNV-1a + splitmix64），
// 保证树的期望平衡性与告警到达顺序无关。
func hashPriority(tenantID, alertID string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(tenantID); i++ {
		h ^= uint64(tenantID[i])
		h *= 1099511628211
	}
	h ^= 0xff
	h *= 1099511628211
	for i := 0; i < len(alertID); i++ {
		h ^= uint64(alertID[i])
		h *= 1099511628211
	}
	// splitmix64 终态混淆
	h += 0x9e3779b97f4a7c15
	h = (h ^ (h >> 30)) * 0xbf58476d1ce4e5b9
	h = (h ^ (h >> 27)) * 0x94d049bb133111eb
	return h ^ (h >> 31)
}

// treap 是分区内告警的有序索引；配合有序双向链表，
// 插入与定位均为期望 O(log N)，前驱/后继访问为 O(1)。
type treap struct {
	root *node
}

func rotateLeft(x *node) *node {
	y := x.right
	x.right = y.left
	y.left = x
	return y
}

func rotateRight(x *node) *node {
	y := x.left
	x.left = y.right
	y.right = x
	return y
}

// insert 将 n 插入 treap（键唯一，调用方保证不存在同键节点），
// 并把 n 拼入有序双向链表。
func (t *treap) insert(n *node) {
	// 插入前用一次 BST 下降找到后继（键大于 n 的最小节点）。
	var pred, succ *node
	cur := t.root
	for cur != nil {
		if less(n, cur) {
			succ = cur
			cur = cur.left
		} else {
			pred = cur
			cur = cur.right
		}
	}
	t.root = insertRec(t.root, n)
	// 拼入有序双向链表。
	n.prev = pred
	n.next = succ
	if pred != nil {
		pred.next = n
	}
	if succ != nil {
		succ.prev = n
	}
}

func insertRec(root, n *node) *node {
	if root == nil {
		return n
	}
	if less(n, root) {
		root.left = insertRec(root.left, n)
		if root.left.prio < root.prio {
			root = rotateRight(root)
		}
	} else {
		root.right = insertRec(root.right, n)
		if root.right.prio < root.prio {
			root = rotateLeft(root)
		}
	}
	return root
}
