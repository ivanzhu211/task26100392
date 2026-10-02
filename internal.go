package correlate

// alertNode is one ingested alert. It is simultaneously a union-find element
// and (via its key) an element of its partition's ordered set.
type alertNode struct {
	id   string
	time int64

	parent *alertNode // union-find parent; nil while unclustered
	root   *ufRoot    // valid only when parent == self
}

// ufRoot holds per-component aggregates, maintained at the union-find root.
type ufRoot struct {
	minID   string
	count   int
	minTime int64
	maxTime int64
	members []*alertNode // unsorted; merged smaller-into-larger on union
}

// partitionKey identifies a correlation partition: alerts in different
// partitions never correlate.
type partitionKey struct {
	endpointID     string
	correlationKey string
}

// tenantState holds everything known about one tenant.
type tenantState struct {
	alerts     map[string]*alertNode   // alert_id -> node (dedup + Locate)
	partitions map[partitionKey]*treap // ordered by (time, id)
}
