// Package correlate implements the alert-correlation component of the MDR
// platform. It merges out-of-order alerts into security events.
//
// Correlation rule, restated for a single partition (tenant, endpoint,
// correlation key) with alerts sorted by (occurred_at, alert_id):
//
//   - Any three distinct alerts whose max-min occurred_at is <= Window form a
//     valid evidence group.
//   - Two groups sharing an alert belong to the same event; this is transitive.
//
// Consecutive alerts a, b in the sorted order are "linked" iff some valid
// evidence group contains both, i.e. prev(a),a,b fit in Window or a,b,next(b)
// fit in Window. Linked consecutive pairs exactly determine the connected
// components of the co-membership graph: any valid group [lo..hi] links every
// consecutive pair inside it, and every link is witnessed by a group. Events
// are precisely the components of size >= 3 (a link always drags in a third
// alert, so no size-2 component exists). Components only ever merge as alerts
// arrive, never split, so a union-find over alerts suffices.
package correlate

import "sort"

// Window is the maximum span (max-min occurred_at, inclusive) of a valid
// evidence group, in milliseconds (10 minutes).
const Window int64 = 600000

// Alert is a single detection alert delivered to the correlator.
type Alert struct {
	TenantID       string
	EndpointID     string
	CorrelationKey string
	AlertID        string
	OccurredAt     int64 // non-negative millisecond timestamp
}

// EventSummary describes the event an alert currently belongs to.
type EventSummary struct {
	EventID string // lexicographically smallest member alert_id
	Count   int    // number of member alerts
	MinTime int64  // earliest occurred_at among members
	MaxTime int64  // latest occurred_at among members
}

// Member is one alert of an event, as returned by Members.
type Member struct {
	AlertID    string
	OccurredAt int64
}

// Correlator merges alerts into security events. Not safe for concurrent use.
type Correlator struct {
	tenants map[string]*tenantState
}

// New returns an empty Correlator.
func New() *Correlator {
	return &Correlator{tenants: make(map[string]*tenantState)}
}

// Add ingests one alert and returns the summary of the event it currently
// belongs to. The second result is false while the alert is not part of any
// event. Re-submitting an identical alert_id is a no-op besides reporting.
func (c *Correlator) Add(a Alert) (EventSummary, bool) {
	ts := c.tenants[a.TenantID]
	if ts == nil {
		ts = &tenantState{
			alerts:     make(map[string]*alertNode),
			partitions: make(map[partitionKey]*treap),
		}
		c.tenants[a.TenantID] = ts
	}
	if node, ok := ts.alerts[a.AlertID]; ok {
		return summaryOf(node)
	}

	node := &alertNode{id: a.AlertID, time: a.OccurredAt}
	ts.alerts[a.AlertID] = node

	pk := partitionKey{endpointID: a.EndpointID, correlationKey: a.CorrelationKey}
	tr := ts.partitions[pk]
	if tr == nil {
		tr = &treap{rng: 0x9e3779b97f4a7c15}
		ts.partitions[pk] = tr
	}
	tr.insert(node)

	// A new alert can only add links, never remove them. Inserting node
	// affects the link condition of at most four consecutive pairs: the two
	// new pairs (pred, node) and (node, succ), plus (predOfPred, pred) whose
	// nextB changed and (succ, succOfSucc) whose prevA changed.
	if pred := tr.pred(node); pred != nil {
		evalPair(tr, pred, node)
		if pp := tr.pred(pred); pp != nil {
			evalPair(tr, pp, pred)
		}
	}
	if succ := tr.succ(node); succ != nil {
		evalPair(tr, node, succ)
		if ss := tr.succ(succ); ss != nil {
			evalPair(tr, succ, ss)
		}
	}
	return summaryOf(node)
}

// evalPair unions consecutive alerts a < b (a immediately precedes b in the
// partition) when some valid evidence group contains both.
func evalPair(tr *treap, a, b *alertNode) {
	linked := false
	if prevA := tr.pred(a); prevA != nil && b.time-prevA.time <= Window {
		linked = true
	} else if nextB := tr.succ(b); nextB != nil && nextB.time-a.time <= Window {
		linked = true
	}
	if linked {
		union(a, b)
	}
}

// Locate returns the summary of the event the given alert currently belongs
// to, or false if the alert is unknown or not part of any event.
func (c *Correlator) Locate(tenantID, alertID string) (EventSummary, bool) {
	ts := c.tenants[tenantID]
	if ts == nil {
		return EventSummary{}, false
	}
	node, ok := ts.alerts[alertID]
	if !ok {
		return EventSummary{}, false
	}
	return summaryOf(node)
}

// Members returns all members of the event the given alert belongs to,
// ordered by (occurred_at, alert_id). It returns nil while the alert is not
// part of any event.
func (c *Correlator) Members(tenantID, alertID string) []Member {
	ts := c.tenants[tenantID]
	if ts == nil {
		return nil
	}
	node, ok := ts.alerts[alertID]
	if !ok {
		return nil
	}
	root := find(node)
	if root.root == nil || root.root.count < 3 {
		return nil
	}
	members := make([]Member, 0, len(root.root.members))
	for _, m := range root.root.members {
		members = append(members, Member{AlertID: m.id, OccurredAt: m.time})
	}
	sort.Slice(members, func(i, j int) bool {
		if members[i].OccurredAt != members[j].OccurredAt {
			return members[i].OccurredAt < members[j].OccurredAt
		}
		return members[i].AlertID < members[j].AlertID
	})
	return members
}

// summaryOf reports the event summary of node's component, or false while
// the component is not an event (fewer than 3 alerts, hence no valid group).
func summaryOf(node *alertNode) (EventSummary, bool) {
	root := find(node)
	if root.root == nil || root.root.count < 3 {
		return EventSummary{}, false
	}
	r := root.root
	return EventSummary{EventID: r.minID, Count: r.count, MinTime: r.minTime, MaxTime: r.maxTime}, true
}

// find returns the union-find root of n, compressing the path.
func find(n *alertNode) *alertNode {
	if n.parent == nil {
		return n
	}
	root := n
	for root.parent != nil {
		root = root.parent
	}
	for n.parent != nil {
		n.parent, n = root, n.parent
	}
	return root
}

// union merges the components of a and b (both already linked). The smaller
// member list is folded into the larger, so no merge ever rewrites all old
// members of the larger side.
func union(a, b *alertNode) {
	ra, rb := find(a), find(b)
	if ra == rb {
		return
	}
	if ra.root == nil {
		ra.root = &ufRoot{
			minID:   ra.id,
			count:   1,
			minTime: ra.time,
			maxTime: ra.time,
			members: []*alertNode{ra},
		}
	}
	if rb.root == nil {
		rb.root = &ufRoot{
			minID:   rb.id,
			count:   1,
			minTime: rb.time,
			maxTime: rb.time,
			members: []*alertNode{rb},
		}
	}
	if len(ra.root.members) < len(rb.root.members) {
		ra, rb = rb, ra
	}
	r, o := ra.root, rb.root
	if o.minID < r.minID {
		r.minID = o.minID
	}
	r.count += o.count
	if o.minTime < r.minTime {
		r.minTime = o.minTime
	}
	if o.maxTime > r.maxTime {
		r.maxTime = o.maxTime
	}
	r.members = append(r.members, o.members...)
	rb.root = nil
	rb.parent = ra
}
