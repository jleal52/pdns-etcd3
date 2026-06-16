//go:build unit

package src

import (
	"testing"
	"time"
)

// builds: apex (example.) with SOA + A; child "www" with A; child "child" that is a
// separate zone (has SOA) and must be EXCLUDED from the parent's walk.
func buildTestZone() *dataNode {
	rec := func(content string) map[string]recordType {
		return map[string]recordType{"": {content: content, ttl: time.Hour}}
	}
	// root the tree at an empty-lname node, matching how the real dataRoot is built
	// (newDataNode(nil, "", "", ...)); getName() relies on that terminator when
	// walking parents, so an apex with a nil parent and a non-empty lname would panic.
	root := newDataNode(nil, "", "", false)
	apex := newDataNode(root, "example", "", false)
	root.children["example"] = apex
	apex.records["SOA"] = map[string]recordType{"": {content: "ns1.example. hostmaster.example. 1 2 3 4 5", ttl: time.Hour}}
	apex.records["A"] = rec("192.0.2.1")
	www := newDataNode(apex, "www", ".", false)
	www.records["A"] = rec("192.0.2.2")
	apex.children["www"] = www
	deleg := newDataNode(apex, "child", ".", false)
	deleg.records["SOA"] = map[string]recordType{"": {content: "ns1.child.example. hostmaster.child.example. 1 2 3 4 5", ttl: time.Hour}}
	deleg.records["A"] = rec("192.0.2.9")
	apex.children["child"] = deleg
	return apex
}

func TestWalkZoneRecords(t *testing.T) {
	apex := buildTestZone()
	var result []objectType[any]
	apex.RLock(false)
	apex.walkZoneRecords(4, &result)
	apex.RUnlock(false)

	counts := map[string]int{}
	for _, item := range result {
		counts[item["qtype"].(string)]++
	}
	// apex SOA + apex A + www A = 3; the child zone's SOA/A are excluded.
	if len(result) != 3 {
		Errorf(t, "got %d items, want 3: %v", len(result), result)
	}
	if counts["SOA"] != 1 || counts["A"] != 2 {
		Errorf(t, "qtype counts wrong: %v", counts)
	}
}
