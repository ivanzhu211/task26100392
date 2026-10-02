package correlate

// treap is a randomized balanced BST keyed by (time, id), giving O(log n)
// expected insert plus predecessor/successor lookup.
type treapNode struct {
	key      *alertNode
	priority uint32
	left     *treapNode
	right    *treapNode
}

type treap struct {
	root *treapNode
	size int
	rng  uint64 // xorshift64 state
}

func less(a, b *alertNode) bool {
	if a.time != b.time {
		return a.time < b.time
	}
	return a.id < b.id
}

func (t *treap) nextPriority() uint32 {
	t.rng ^= t.rng << 13
	t.rng ^= t.rng >> 7
	t.rng ^= t.rng << 17
	return uint32(t.rng)
}

func rotateLeft(n *treapNode) *treapNode {
	r := n.right
	n.right = r.left
	r.left = n
	return r
}

func rotateRight(n *treapNode) *treapNode {
	l := n.left
	n.left = l.right
	l.right = n
	return l
}

// insert adds key to the set. The key must not already be present.
func (t *treap) insert(key *alertNode) {
	n := &treapNode{key: key, priority: t.nextPriority()}
	t.root = insertNode(t.root, n)
	t.size++
}

func insertNode(root, n *treapNode) *treapNode {
	if root == nil {
		return n
	}
	if less(n.key, root.key) {
		root.left = insertNode(root.left, n)
		if root.left.priority < root.priority {
			root = rotateRight(root)
		}
	} else {
		root.right = insertNode(root.right, n)
		if root.right.priority < root.priority {
			root = rotateLeft(root)
		}
	}
	return root
}

// pred returns the greatest element strictly less than key, or nil.
func (t *treap) pred(key *alertNode) *alertNode {
	var best *alertNode
	for n := t.root; n != nil; {
		if less(n.key, key) {
			best = n.key
			n = n.right
		} else {
			n = n.left
		}
	}
	return best
}

// succ returns the smallest element strictly greater than key, or nil.
func (t *treap) succ(key *alertNode) *alertNode {
	var best *alertNode
	for n := t.root; n != nil; {
		if less(key, n.key) {
			best = n.key
			n = n.left
		} else {
			n = n.right
		}
	}
	return best
}
