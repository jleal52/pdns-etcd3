# AXFR Zone-Transfer (Primary Mode) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make pdns-etcd3 serve outbound AXFR so PowerDNS can act as an authoritative primary, with automatic NOTIFY to an external secondary, TSIG-secured transfers, and correct behavior for pre-signed DNSSEC zones.

**Architecture:** All work is adding JSON-RPC methods to the remote-backend dispatch (`src/pdns-etcd3.go` `handleRequest`) plus the data-layer logic behind them. PowerDNS speaks the AXFR/TCP protocol and sends NOTIFY; the backend only supplies data: the full record list (`list`), the set of changed zones (`getUpdatedMasters`) + remembered notified serials (`setNotified`), and TSIG keys (`getTSIGKey`/`getTSIGKeys`). The in-memory tree (`dataNode`) is walked under read-locks; the slow TCP transfer happens in PowerDNS after the backend responds, so no backend lock is held during it.

**Tech Stack:** Go 1.21+ (generics), `go.etcd.io/etcd/client/v3`, PowerDNS remote backend (JSON over stream / HTTP), tests via `-tags unit` (in-process) and `-tags integration` (testcontainers: etcd + PowerDNS, resolved with `github.com/miekg/dns`, including `dns.Transfer` for AXFR client tests).

**Design reference:** `docs/plans/2026-06-16-zone-transfer-axfr-design.md` (decisions in §10). This plan REFINES design decision R4: `notified_serial` is kept **in-memory** (not in etcd) to avoid a NOTIFY feedback loop — see Phase F2 preamble.

**Conventions to respect (from CLAUDE.md):**
- The package is literally `src`. Generics are used pervasively.
- Read-lock dance: `getChild(name, countReader)` RLocks every node on the path; caller MUST `defer data.rUnlockUpwards(nil, countReader)`. `countReader` must match.
- A node is a zone iff `hasSOA()`. `findZone()` walks up.
- Changing on-etcd key/value shape ⇒ bump `dataVersion` in `src/data.go` AND `doc/ETCD-structure.md` AND the build workflow.
- `log.Fatal*` is deprecated; use `Panic*`. Use `log.main()/pdns()/etcd()/data()` components.
- Build/test via the Makefile. Single test: `make unit-tests ONLY=TestName VERBOSE=1`.

**Phases:** F1 AXFR core (`list` + serial projection + zone identity + kind) → F2 automatic NOTIFY (`getUpdatedMasters`/`setNotified`) → F3 TSIG → F4 DNSSEC pre-signed → Transversal (versioning, docs).

**Commit discipline:** one commit per task (after its tests pass). End every commit message with the `Co-Authored-By` trailer this repo uses.

---

## PHASE F1 — AXFR core

Net effect after F1: PowerDNS configured `primary=yes` + `allow-axfr-ips` can serve a full AXFR of an unsigned zone backed by etcd, with a stable `uint32` SOA serial.

### Task 1: SOA serial projected to uint32

**Why:** Secondaries compare serials as `uint32` (RFC 1982). Today the raw etcd revision (`int64`) is printed verbatim (`src/rr.go:350`), which can exceed `uint32`. Project it explicitly; `X-PE3-FIXED-SERIAL` keeps precedence (it already returns a validated uint32 through `soaSerial`).

**Files:**
- Modify: `src/rr.go` (add `soaWireSerial`, use it in `soa()` at line ~323/350)
- Test: `src/dnssec_test.go` (new `TestSOAWireSerial`)

**Step 1: Write the failing test**

Add to `src/dnssec_test.go`:

```go
// TestSOAWireSerial: the wire serial is soaSerial() projected onto uint32.
func TestSOAWireSerial(t *testing.T) {
	for i, spec := range []test[func(*dataNode), uint32]{
		// plain zoneRev within uint32
		{func(dn *dataNode) { dn.maxRev = 42 }, ve[uint32]{v: 42}},
		// zoneRev above uint32 wraps (4294967296 + 5)
		{func(dn *dataNode) { dn.maxRev = 4294967301 }, ve[uint32]{v: 5}},
		// FIXED-SERIAL takes precedence and round-trips exactly
		{func(dn *dataNode) { dn.maxRev = 9; dn.metadata[MetaFixedSerial] = []string{"100"} }, ve[uint32]{v: 100}},
	} {
		tf := func(_ *testing.T, setup func(*dataNode)) (uint32, error) {
			dn := newDataNode(nil, "", "TEST/", false)
			setup(dn)
			return soaWireSerial(dn), nil
		}
		checkRun(t, fmt.Sprintf("(%d)", i+1), tf, spec.input, spec.expected, false)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `make unit-tests ONLY=TestSOAWireSerial`
Expected: FAIL — `undefined: soaWireSerial`.

**Step 3: Write minimal implementation**

In `src/rr.go`, just below `soaSerial` (after line 284):

```go
// soaWireSerial projects the (possibly >uint32) automatic serial onto uint32 for
// the SOA wire format. Monotone under RFC 1982 because increments between secondary
// polls always stay far below 2^31. X-PE3-FIXED-SERIAL still takes precedence (it is
// validated as uint32 inside soaSerial).
func soaWireSerial(data *dataNode) uint32 {
	return uint32(soaSerial(data))
}
```

In `soa()` change the serial line (was `serial := soaSerial(params.data)`):

```go
	// serial: projected onto uint32; MetaFixedSerial overrides zoneRev (e.g. to match RRSIG(SOA)).
	serial := soaWireSerial(params.data)
```

`fmt.Sprintf("%s %s %d ...", primary, mail, serial, ...)` prints a `uint32` correctly.

**Step 4: Run tests to verify they pass**

Run: `make unit-tests ONLY='TestSOAWireSerial|TestFixedSerial|TestSOA'`
Expected: PASS (existing SOA tests still green).

**Step 5: Commit**

```bash
git add src/rr.go src/dnssec_test.go
git commit -m "feat: project SOA serial onto uint32 for wire format

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Zone-id registry (stable domain_id ↔ zone, in-memory notified serial)

**Why:** `list`, `getDomainInfo`, `getAllDomains`, `getUpdatedMasters` expose an integer `domain_id`; `setNotified` only receives that id. Need a bidirectional registry. It also holds the in-memory `notified_serial` (see F2 preamble).

**Files:**
- Create: `src/zoneid.go`
- Test: `src/zoneid_test.go`

**Step 1: Write the failing test**

`src/zoneid_test.go`:

```go
//go:build unit

package src

import (
	"fmt"
	"testing"
)

func TestZoneRegistry(t *testing.T) {
	r := newZoneRegistry()
	idA := r.id("a.example.")
	idB := r.id("b.example.")
	// stable: same name → same id
	if r.id("a.example.") != idA {
		Errorf(t, "id not stable for a.example.")
	}
	// distinct names → distinct ids
	if idA == idB {
		Errorf(t, "ids collided: %d", idA)
	}
	// reverse lookup
	if name, ok := r.name(idB); !ok || name != "b.example." {
		Errorf(t, "reverse lookup failed: %q ok=%v", name, ok)
	}
	if _, ok := r.name(999999); ok {
		Errorf(t, "unknown id resolved")
	}
	// notified serial round-trips by name; default 0
	if r.notifiedSerial("a.example.") != 0 {
		Errorf(t, "default notified serial not 0")
	}
	r.setNotified("a.example.", 12345)
	if got := r.notifiedSerial("a.example."); got != 12345 {
		Errorf(t, "notified serial = %d, want 12345", got)
	}
}
```

**Step 2: Run to verify it fails**

Run: `make unit-tests ONLY=TestZoneRegistry`
Expected: FAIL — `undefined: newZoneRegistry`.

**Step 3: Write minimal implementation**

`src/zoneid.go`:

```go
/* Copyright 2016-2026 nix <https://keybase.io/nixn> ... (copy the standard header from another src file) */

package src

import "sync"

// zoneRegistry assigns stable integer ids to zones (the PowerDNS domain_id used by
// list/getDomainInfo/getAllDomains/getUpdatedMasters/setNotified) and remembers the
// last serial PowerDNS notified secondaries about.
//
// Both maps are process-local: ids need only be stable within one process run, and the
// notified serial is deliberately NOT persisted to etcd (persisting it under the zone
// prefix would bump the zone revision and thus the serial, causing an endless NOTIFY
// loop). Consequence: after a pe3 restart every zone looks "updated" once, producing a
// single harmless re-NOTIFY round. Primary operation therefore expects standalone mode.
type zoneRegistry struct {
	mutex    sync.Mutex
	byName   map[string]int64
	byID     map[int64]string
	notified map[string]uint32
	nextID   int64
}

func newZoneRegistry() *zoneRegistry {
	return &zoneRegistry{
		byName:   map[string]int64{},
		byID:     map[int64]string{},
		notified: map[string]uint32{},
	}
}

// zoneIDs is the global registry.
var zoneIDs = newZoneRegistry()

func (r *zoneRegistry) id(qname string) int64 {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if id, ok := r.byName[qname]; ok {
		return id
	}
	r.nextID++
	r.byName[qname] = r.nextID
	r.byID[r.nextID] = qname
	return r.nextID
}

func (r *zoneRegistry) name(id int64) (string, bool) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	qname, ok := r.byID[id]
	return qname, ok
}

func (r *zoneRegistry) notifiedSerial(qname string) uint32 {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.notified[qname]
}

func (r *zoneRegistry) setNotified(qname string, serial uint32) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.notified[qname] = serial
}
```

**Step 4: Run to verify it passes**

Run: `make unit-tests ONLY=TestZoneRegistry`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/zoneid.go src/zoneid_test.go
git commit -m "feat: add in-memory zone-id registry for PDNS domain_id + notified serial

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Zone-walk producing AXFR result items

**Why:** `list` must return every record of the zone (apex + non-zone descendants, stopping at delegated sub-zones that have their own SOA). No such walk exists today. Reuse `makeResultItem` (auth refinement deferred to F4).

**Files:**
- Modify: `src/lookup.go` (add `walkZoneRecords`)
- Test: `src/lookup_test.go` (create; `//go:build unit`)

**Step 1: Write the failing test**

`src/lookup_test.go`:

```go
//go:build unit

package src

import (
	"testing"
	"time"
)

// builds: apex (example.) with SOA + A; child "www" with A; child "deleg" that is a
// separate zone (has SOA) and must be EXCLUDED from the parent's walk.
func buildTestZone() *dataNode {
	rec := func(content string) map[string]recordType {
		return map[string]recordType{"": {content: content, ttl: time.Hour}}
	}
	apex := newDataNode(nil, "example", "", false)
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
```

**Step 2: Run to verify it fails**

Run: `make unit-tests ONLY=TestWalkZoneRecords`
Expected: FAIL — `apex.walkZoneRecords undefined`.

**Step 3: Write minimal implementation**

In `src/lookup.go` (after `makeResultItem`):

```go
// walkZoneRecords appends every record of the zone rooted at dn — its own records plus
// those of all descendant nodes that are NOT themselves zones (no SOA) — to result, as
// PowerDNS result items. The receiver must be RLocked by the caller; each descendant is
// RLocked/RUnlocked here (parent-before-child, matching getChild's lock order).
func (dn *dataNode) walkZoneRecords(pdnsVersion uint, result *[]objectType[any]) {
	qname := dn.getName()
	for qtype, byID := range dn.records {
		for _, record := range byID {
			record := record
			*result = append(*result, makeResultItem(qname, qtype, dn, &record, pdnsVersion))
		}
	}
	for _, child := range dn.children {
		child.RLock(false)
		if !child.hasSOA() { // stop at delegated sub-zones (own SOA)
			child.walkZoneRecords(pdnsVersion, result)
		}
		child.RUnlock(false)
	}
}
```

**Step 4: Run to verify it passes**

Run: `make unit-tests ONLY=TestWalkZoneRecords`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/lookup.go src/lookup_test.go
git commit -m "feat: add zone-subtree record walk for AXFR

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: `list` handler + dispatch

**Why:** Wire the walk into the remote-backend `list` method PowerDNS calls for AXFR.

**Files:**
- Modify: `src/lookup.go` (add `func (cr *pdnsClientRequest) list()`)
- Modify: `src/pdns-etcd3.go` (add `case "list"` at ~line 240)

**Step 1: Write the failing test** — unit test the handler-less core is covered by Task 3; add a dispatch-presence test that asserts the case exists by calling through a minimal request is heavy, so test the handler's "not our zone → false" branch:

`src/lookup_test.go` (append):

```go
func TestListNotOurZone(t *testing.T) {
	// dataRoot has no zones; list of anything returns false (refused), not an empty slice.
	dataRoot = newDataNode(nil, "", "", false)
	cr := &pdnsClientRequest{Client: testClient(t), Request: &pdnsRequest{
		Method: "list", Parameters: objectType[any]{"zonename": "absent.example.", "domain_id": float64(-1)},
	}}
	res, err := cr.list()
	if err != nil {
		Errorf(t, "unexpected error: %s", err)
	}
	if res != false {
		Errorf(t, "want false for unknown zone, got %#v", res)
	}
}
```

> If a `testClient(t)` helper does not already exist, add a tiny one in `src/common_test.go` that returns a `*pdnsClient` with `PdnsVersion: 4` and a no-op logger (mirror how other tests obtain a client; check existing `*_test.go` first and reuse).

**Step 2: Run to verify it fails**

Run: `make unit-tests ONLY=TestListNotOurZone`
Expected: FAIL — `cr.list undefined`.

**Step 3: Write minimal implementation**

In `src/lookup.go`:

```go
func (cr *pdnsClientRequest) list() (any, error) {
	zonename := ParseDomainName(strings.ToLower(cr.Request.Parameters["zonename"].(string)))
	//goland:noinspection GoPreferNilSlice
	result := []objectType[any]{}
	lockDebug := cr.Client.Logf(4, "data", "locking")
	lockDebug("list: RLocking up to %q", Supplier1(zonename.asKey, true))()
	data, found := dataRoot.getChild(zonename, true)
	defer data.rUnlockUpwards(nil, true)
	defer lockDebug("list: RUnlocking %q", data.prefixKey)(data.LockCounts)
	if !found || !data.hasSOA() {
		cr.Client.Logf(1, "data")("list: not a served zone")(zonename.normal)
		return false, nil // refuse AXFR for zones we don't hold
	}
	data.walkZoneRecords(cr.Client.PdnsVersion, &result)
	cr.Client.Logf(1, "pdns")("list: result")("zone", zonename.normal, "#", len(result))
	return result, nil
}
```

In `src/pdns-etcd3.go` `handleRequest` switch, after the `getdomaininfo` case:

```go
	case "list":
		result, err = cr.list()
```

**Step 4: Run to verify it passes**

Run: `make unit-tests ONLY='TestList|TestWalkZoneRecords'`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/lookup.go src/pdns-etcd3.go src/common_test.go
git commit -m "feat: implement remote-backend list method (AXFR-OUT)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: `getDomainInfo` + `getAllDomains` report kind/id/notified_serial

**Why:** PowerDNS's primary thread only considers zones whose `kind` is `MASTER` and needs `id` and `serial`. `serial` must equal the AXFR'd SOA (the uint32 projection).

**Files:**
- Modify: `src/metadata.go` (`getDomainInfo`)
- Modify: `src/data.go` (`domainInfo` struct + `allDomains`)

**Step 1: Write the failing test**

`src/data_test.go` (append; mirror existing style/build tag):

```go
func TestAllDomainsReportsKindAndID(t *testing.T) {
	apex := newDataNode(nil, "example", "", false)
	apex.records["SOA"] = map[string]recordType{"": {content: "ns1 host 1 2 3 4 5"}}
	apex.maxRev = 7
	got := apex.allDomains([]domainInfo{})
	if len(got) != 1 {
		Fatalf(t, "want 1 domain, got %d", len(got))
	}
	if got[0].Kind != "MASTER" {
		Errorf(t, "kind = %q, want MASTER", got[0].Kind)
	}
	if got[0].ID == 0 {
		Errorf(t, "id not assigned")
	}
	if got[0].Serial != 7 {
		Errorf(t, "serial = %d, want 7", got[0].Serial)
	}
}
```

**Step 2: Run to verify it fails**

Run: `make unit-tests ONLY=TestAllDomainsReportsKindAndID`
Expected: FAIL — unknown field `Kind`.

**Step 3: Write minimal implementation**

In `src/data.go`, replace the `domainInfo` struct and `allDomains` body:

```go
type domainInfo struct {
	ID             int64  `json:"id"`
	Zone           string `json:"zone"`
	Serial         int64  `json:"serial"`
	NotifiedSerial int64  `json:"notified_serial"`
	Kind           string `json:"kind"`
}

func (dn *dataNode) allDomains(result []domainInfo) []domainInfo {
	if dn.hasSOA() {
		zone := dn.getQname()
		result = append(result, domainInfo{
			ID:             zoneIDs.id(zone),
			Zone:           zone,
			Serial:         int64(soaWireSerial(dn)),
			NotifiedSerial: int64(zoneIDs.notifiedSerial(zone)),
			Kind:           "MASTER",
		})
	}
	for _, child := range dn.children {
		result = child.allDomains(result)
	}
	return result
}
```

In `src/metadata.go` `getDomainInfo`, replace the returned object:

```go
		zone := data.getQname()
		return objectType[any]{
			"id":              zoneIDs.id(zone),
			"zone":            cr.Request.Parameters["name"],
			"serial":          int64(soaWireSerial(data)),
			"notified_serial": int64(zoneIDs.notifiedSerial(zone)),
			"kind":            "MASTER",
		}, nil
```

**Step 4: Run to verify it passes**

Run: `make unit-tests ONLY='TestAllDomains|TestGetDomainInfo'`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/data.go src/metadata.go src/data_test.go
git commit -m "feat: report MASTER kind, domain_id and notified_serial in domain info

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Integration test — AXFR end-to-end (unsigned)

**Why:** Prove `list` actually transfers a zone through a real PowerDNS, using a `dns.Transfer` AXFR client (no separate secondary server needed yet).

**Files:**
- Modify: `src/integration_test.go` (new `TestAXFR`; if `startPDNS` does not allow AXFR, add an `allow-axfr-ips=0.0.0.0/0,::/0` + `primary=yes`/`master=yes` setting toggled by version)

**Step 1: Write the failing test** (sketch — follow the exact helper signatures already in the file)

```go
//go:build integration

func TestAXFR(t *testing.T) {
	defer recoverPanicsT(t)
	etcd, err := startETCD(t); fatalOnErr(t, "start ETCD", err); defer etcd.Terminate()
	pe3 := startPE3(t, etcd.Endpoint, "", "-pdns-version="+getenvT("PDNS_VERSION", "50")[:1]); defer pe3.Terminate()
	fatalOnErr(t, "PE3 ready", waitFor(t, "PE3", func() bool { return status.serving }, 10*time.Millisecond, 30*time.Second))
	// seed a minimal zone into etcd: SOA + NS + A  (use the same etcd client helper other tests use)
	seedZone(t, etcd.Endpoint, "example.test.")
	pdns, err := startPDNS(t, map[string]string{
		"primary=yes":                 "44", // master=yes for <4.5 — branch on version in startPDNS
		"allow-axfr-ips=0.0.0.0/0,::/0": "34",
	}); fatalOnErr(t, "start PDNS", err); defer pdns.Terminate()
	// AXFR via miekg/dns
	tr := new(dns.Transfer)
	m := new(dns.Msg); m.SetAxfr("example.test.")
	ch, err := tr.In(m, pdns.Endpoint); fatalOnErr(t, "axfr", err)
	var soa, a int
	for env := range ch {
		if env.Error != nil { Errorf(t, "axfr env error: %s", env.Error); break }
		for _, rr := range env.RR {
			switch rr.(type) { case *dns.SOA: soa++; case *dns.A: a++ }
		}
	}
	if soa < 2 { Errorf(t, "AXFR must start and end with SOA, saw %d", soa) }
	if a < 1 { Errorf(t, "expected at least one A record, saw %d", a) }
}
```

> Implementation notes for the executor:
> - Reuse/extract a `seedZone` helper from how existing integration tests put data into etcd (search `integration_test.go` for the etcd `clientv3` put pattern; PUT keys like `test/example/SOA`, `test/example/NS`, `test/example/A`).
> - `startPDNS`'s `dynamicSettings` map is `setting -> minVersion`. Add the `primary`/`master` and `allow-axfr-ips` settings, branching `master=yes` for versions `< 45` and `primary=yes` for `>= 45`.
> - `pdns.Endpoint` is the mapped `53/tcp` host:port; `dns.Transfer` defaults to TCP — good.

**Step 2: Run to verify it fails** (then implement seeding/settings until green)

Run: `make integration-tests ONLY=TestAXFR VERBOSE=1`
Expected first: FAIL (zone not transferable) → iterate on settings/seeding.

**Step 3–4:** Implement `seedZone` + settings; re-run until PASS.

**Step 5: Commit**

```bash
git add src/integration_test.go
git commit -m "test: integration AXFR transfer of an unsigned zone

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## PHASE F2 — Automatic NOTIFY

**Preamble (design refinement of R4):** `notified_serial` is held **in memory** in `zoneIDs` (Task 2), NOT persisted to etcd. Persisting it under the zone prefix would raise the zone's `maxRev` → raise the serial → the zone would look "updated" again → endless NOTIFY loop. In-memory state is correct because it only mirrors "what PowerDNS already notified"; losing it on restart just causes one harmless re-NOTIFY. **Primary/NOTIFY operation therefore requires standalone (long-lived) mode** — document this in F-Transversal. `setNotified` becomes a trivial in-memory update (no transaction, no `waitForReload`).

### Task 7: `getUpdatedMasters` / `getUpdatedPrimaries`

**Files:**
- Modify: `src/data.go` (add `updatedDomains`)
- Modify: `src/pdns-etcd3.go` (dispatch both method names)

**Step 1: Write the failing test**

`src/data_test.go` (append):

```go
func TestUpdatedDomains(t *testing.T) {
	zoneIDs = newZoneRegistry()
	apex := newDataNode(nil, "example", "", false)
	apex.records["SOA"] = map[string]recordType{"": {content: "ns1 host 1 2 3 4 5"}}
	apex.maxRev = 10
	// not notified yet → appears as updated
	if got := apex.updatedDomains(nil); len(got) != 1 || got[0].Serial != 10 {
		Fatalf(t, "want 1 updated domain serial 10, got %v", got)
	}
	// after notifying the current serial → no longer updated
	zoneIDs.setNotified("example.", 10)
	if got := apex.updatedDomains(nil); len(got) != 0 {
		Errorf(t, "want 0 updated after notify, got %v", got)
	}
}
```

**Step 2: Run to verify it fails**

Run: `make unit-tests ONLY=TestUpdatedDomains`
Expected: FAIL — `updatedDomains undefined`.

**Step 3: Write minimal implementation**

In `src/data.go`:

```go
// updatedDomains returns the zones whose current serial differs from the last serial
// PowerDNS notified secondaries about (so PowerDNS will send NOTIFY for them).
func (dn *dataNode) updatedDomains(result []domainInfo) []domainInfo {
	if dn.hasSOA() {
		zone := dn.getQname()
		serial := soaWireSerial(dn)
		if serial != zoneIDs.notifiedSerial(zone) {
			result = append(result, domainInfo{
				ID:             zoneIDs.id(zone),
				Zone:           zone,
				Serial:         int64(serial),
				NotifiedSerial: int64(zoneIDs.notifiedSerial(zone)),
				Kind:           "MASTER",
			})
		}
	}
	for _, child := range dn.children {
		result = child.updatedDomains(result)
	}
	return result
}
```

In `src/pdns-etcd3.go` switch:

```go
	case "getupdatedmasters", "getupdatedprimaries":
		result = dataRoot.updatedDomains([]domainInfo{})
```

**Step 4: Run to verify it passes**

Run: `make unit-tests ONLY=TestUpdatedDomains`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/data.go src/pdns-etcd3.go src/data_test.go
git commit -m "feat: getUpdatedMasters/getUpdatedPrimaries for NOTIFY detection

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: `setNotified`

**Files:**
- Modify: `src/metadata.go` (add `setNotified`) + small `paramInt64` helper (put in `src/util.go`)
- Modify: `src/pdns-etcd3.go` (dispatch)

**Step 1: Write the failing test**

`src/util_test.go` (create or append; `//go:build unit`):

```go
func TestParamInt64(t *testing.T) {
	for _, c := range []struct{ in any; want int64; errSub string }{
		{float64(7), 7, ""},
		{"42", 42, ""},
		{int64(5), 5, ""},
		{true, 0, "not a number"},
	} {
		got, err := paramInt64(c.in)
		if c.errSub != "" {
			if err == nil { Errorf(t, "%#v: expected error", c.in) }
			continue
		}
		if err != nil || got != c.want { Errorf(t, "%#v -> %d,%v want %d", c.in, got, err, c.want) }
	}
}
```

**Step 2: Run to verify it fails**

Run: `make unit-tests ONLY=TestParamInt64`
Expected: FAIL — `paramInt64 undefined`.

**Step 3: Write minimal implementation**

In `src/util.go`:

```go
func paramInt64(v any) (int64, error) {
	switch n := v.(type) {
	case float64:
		return int64(n), nil
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	case string:
		return strconv.ParseInt(n, 10, 64)
	default:
		return 0, fmt.Errorf("not a number: %v (%T)", v, v)
	}
}
```

(Add `strconv`/`fmt` to imports if missing.)

In `src/metadata.go`:

```go
func (cr *pdnsClientRequest) setNotified() (bool, error) {
	id, err := paramInt64(cr.Request.Parameters["id"])
	if err != nil {
		return false, fmt.Errorf("bad id: %s", err)
	}
	serial, err := paramInt64(cr.Request.Parameters["serial"])
	if err != nil {
		return false, fmt.Errorf("bad serial: %s", err)
	}
	zone, ok := zoneIDs.name(id)
	if !ok {
		return false, fmt.Errorf("unknown domain id %d", id)
	}
	zoneIDs.setNotified(zone, uint32(serial))
	cr.Logf(2, "main")("setNotified")("zone", zone, "serial", serial)
	return true, nil
}
```

In `src/pdns-etcd3.go` switch:

```go
	case "setnotified":
		result, err = cr.setNotified()
```

**Step 4: Run to verify it passes**

Run: `make unit-tests ONLY=TestParamInt64`
Expected: PASS. Also `make unit-tests` (full) green.

**Step 5: Commit**

```bash
git add src/util.go src/metadata.go src/pdns-etcd3.go src/util_test.go
git commit -m "feat: setNotified records the notified serial in-memory

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 9 (optional, larger): Integration test — NOTIFY to a secondary

**Why:** End-to-end proof that changing etcd makes a real secondary refresh. This is the heaviest task; if time-boxed, rely on the F2 unit tests + the F1 AXFR integration test and defer this.

**Approach:** Start a second DNS server as secondary (a second PowerDNS with `secondary`/`slave` + a `gsqlite3`/`bind` backend slaving `example.test.` from the primary, or NSD with a `pattern` requesting AXFR). Configure the primary with `also-notify=<secondary-ip>`. After initial transfer, PUT a new record into etcd; poll the secondary until it serves the new record (NOTIFY-driven), with a timeout fallback.

**Steps:** write `TestAXFRNotify` (fails) → add `startSecondary` testcontainer helper → wire `also-notify` into `startPDNS` → seed, change, poll → green → commit. Run: `make integration-tests ONLY=TestAXFRNotify VERBOSE=1`.

```bash
git commit -m "test: integration NOTIFY-driven secondary refresh

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## PHASE F3 — TSIG-secured transfers

**Approach (low-risk):** TSIG keys are global named objects stored in etcd under `<prefix>-tsig-/<keyname>` with value `"<algorithm> <base64-secret>"` (e.g. `hmac-sha256 0M6m...==`). `getTSIGKey` reads the key directly from etcd on demand (no tree integration); we only teach the parser/loader to RECOGNIZE and IGNORE `-tsig-` entries so the bulk load doesn't log errors and they never affect any zone serial. Per-zone ACL via `TSIG-ALLOW-AXFR` metadata already works through the existing passthrough — just populate it.

### Task 10: Recognize the `-tsig-` pseudo-entry (parsed, not stored in the tree)

**Files:**
- Modify: `src/const.go` (add `tsigKey = "-tsig-"`)
- Modify: `src/lookup.go` (add `tsigEntry` to the enum + `key2entryType`)
- Modify: `src/data.go` (`parseEntryKey` case; `reload` skip case)
- Test: `src/data_test.go`

**Step 1: Write the failing test**

```go
func TestParseTSIGEntryKey(t *testing.T) {
	*args.Prefix = "" // ensure no prefix during test; restore if other tests rely on it
	name, et, qtype, id, _, err := parseEntryKey("-tsig-/xfrkey")
	if err != nil { Fatalf(t, "unexpected error: %s", err) }
	if et != tsigEntry { Errorf(t, "entryType = %q, want tsig", et) }
	if id != "xfrkey" { Errorf(t, "id = %q, want xfrkey", id) }
	if len(name) != 0 || qtype != "" { Errorf(t, "name/qtype should be empty: %v %q", name, qtype) }
}
```

**Step 2: Run to verify it fails**

Run: `make unit-tests ONLY=TestParseTSIGEntryKey`
Expected: FAIL — `undefined: tsigEntry` (and/or "invalid entry type keyword").

**Step 3: Write minimal implementation**

`src/const.go` — add to the key block:

```go
	tsigKey = "-tsig-"
```

`src/lookup.go` — add to the `entryType` enum and the map:

```go
	tsigEntry     entryType = "tsig"
```
```go
	key2entryType = map[string]entryType{
		defaultsKey: defaultsEntry,
		optionsKey:  optionsEntry,
		metadataKey: metadataEntry,
		lockKey:     lockEntry,
		tsigKey:     tsigEntry,
	}
```

`src/data.go` `parseEntryKey` switch — add a case (the remainder is the key name, may contain dots):

```go
	case tsigEntry:
		id = key
		return
```

`src/data.go` `reload` entry-dispatch switch — add a case that ignores tsig entries (they are read on demand, must not touch the tree or any serial):

```go
	case tsigEntry:
		// global TSIG keys are read on demand by getTSIGKey; never stored in the tree
		continue ITEMS
```

**Step 4: Run to verify it passes**

Run: `make unit-tests ONLY=TestParseTSIGEntryKey`
Expected: PASS. Full `make unit-tests` green.

**Step 5: Commit**

```bash
git add src/const.go src/lookup.go src/data.go src/data_test.go
git commit -m "feat: recognize global -tsig- pseudo-entries (parsed, ignored in tree)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: `getTSIGKey` / `getTSIGKeys` handlers

**Files:**
- Create: `src/tsig.go`
- Modify: `src/pdns-etcd3.go` (dispatch both)

**Step 1: Write the failing test** — unit-test the value parser (the etcd read is covered by integration):

`src/tsig_test.go` (`//go:build unit`):

```go
func TestParseTSIGValue(t *testing.T) {
	algo, secret, err := parseTSIGValue([]byte("hmac-sha256  0M6mHu8K==  "))
	if err != nil { Fatalf(t, "err: %s", err) }
	if algo != "hmac-sha256" || secret != "0M6mHu8K==" {
		Errorf(t, "got %q / %q", algo, secret)
	}
	if _, _, err := parseTSIGValue([]byte("only-one-field")); err == nil {
		Errorf(t, "expected error for malformed value")
	}
}
```

**Step 2: Run to verify it fails**

Run: `make unit-tests ONLY=TestParseTSIGValue`
Expected: FAIL — `parseTSIGValue undefined`.

**Step 3: Write minimal implementation**

`src/tsig.go`:

```go
package src

import (
	"fmt"
	"strings"
)

func parseTSIGValue(raw []byte) (algorithm, secret string, err error) {
	fields := strings.Fields(string(raw))
	if len(fields) != 2 {
		return "", "", fmt.Errorf("TSIG value must be '<algorithm> <base64-secret>'")
	}
	return fields[0], fields[1], nil
}

func (cr *pdnsClientRequest) getTSIGKey() (any, error) {
	name := cr.Request.Parameters["name"].(string)
	key := *args.Prefix + tsigKey + keySeparator + name
	resp, err := cli.Get(key, false, nil, *args.DialTimeout)
	if err != nil {
		return false, fmt.Errorf("etcd get failed: %s", err)
	}
	for item := range resp.DataChan {
		algo, secret, perr := parseTSIGValue(item.Value)
		if perr != nil {
			return false, perr
		}
		return objectType[any]{"name": name, "algorithm": algo, "content": secret}, nil
	}
	return false, nil // unknown key
}

func (cr *pdnsClientRequest) getTSIGKeys() (any, error) {
	prefix := *args.Prefix + tsigKey + keySeparator
	resp, err := cli.Get(prefix, true, nil, *args.DialTimeout)
	if err != nil {
		return false, fmt.Errorf("etcd get failed: %s", err)
	}
	//goland:noinspection GoPreferNilSlice
	keys := []objectType[any]{}
	for item := range resp.DataChan {
		name := strings.TrimPrefix(item.Key, prefix)
		algo, secret, perr := parseTSIGValue(item.Value)
		if perr != nil {
			cr.Errorf("data")("skipping malformed TSIG key %q: %s", name, perr)()
			continue
		}
		keys = append(keys, objectType[any]{"name": name, "algorithm": algo, "content": secret})
	}
	return keys, nil
}
```

> Verify the exact `cli.Get` signature/return type against `src/etcd.go` (the executor saw it used as `cli.Get(prefix, true, nil, timeout)` returning a value with a `.DataChan` of `etcdItem` whose fields are `.Key string` / `.Value []byte`). Adjust the range/return if the helper differs.

In `src/pdns-etcd3.go` switch:

```go
	case "gettsigkey":
		result, err = cr.getTSIGKey()
	case "gettsigkeys":
		result, err = cr.getTSIGKeys()
```

**Step 4: Run to verify it passes**

Run: `make unit-tests ONLY=TestParseTSIGValue`
Expected: PASS. Full `make unit-tests` green.

**Step 5: Commit**

```bash
git add src/tsig.go src/pdns-etcd3.go src/tsig_test.go
git commit -m "feat: getTSIGKey/getTSIGKeys reading -tsig- keys from etcd

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 12: Integration test — TSIG-protected AXFR

**Files:** Modify `src/integration_test.go` (`TestAXFRTSIG`).

**Approach:** PUT a TSIG key into etcd (`<prefix>-tsig-/xfr. = "hmac-sha256 <base64>"`) and the zone metadata `TSIG-ALLOW-AXFR = ["xfr."]`; configure the primary to require TSIG (drop `allow-axfr-ips`, rely on TSIG). AXFR with `dns.Transfer{TsigSecret: {"xfr.": "<base64>"}}` + `m.SetTsig("xfr.", dns.HmacSHA256, 300, time.Now().Unix())` → expect success; a second AXFR without TSIG → expect refusal/error.

Run: `make integration-tests ONLY=TestAXFRTSIG VERBOSE=1`. Commit when green.

```bash
git commit -m "test: integration TSIG-secured AXFR (accept signed, refuse unsigned)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## PHASE F4 — DNSSEC pre-signed over AXFR

Pre-signed records (DNSKEY/RRSIG/NSEC/NSEC3/DS/CDS/CDNSKEY) are already stored as plain strings and served verbatim, so the F1 `list` walk already emits them. What's missing: correct `auth` flags for delegations and the `PRESIGNED` zone metadata so PowerDNS streams the stored RRSIGs instead of trying to re-sign. Serial coherence with `RRSIG(SOA)` is already handled by `X-PE3-FIXED-SERIAL` (Task 1 keeps its precedence).

### Task 13: Correct `auth` flag for delegations/glue in the AXFR walk

**Why:** At a delegation point, the delegation `NS` and any glue `A`/`AAAA` below it must be `auth=0`; everything else `auth=1`. `makeResultItem` currently sets `auth = (findZone() != nil)` → always true inside a zone. Add a list-specific override.

**Files:**
- Modify: `src/lookup.go` (`walkZoneRecords` carries a `belowDelegation` flag and overrides `auth`)
- Test: `src/lookup_test.go`

**Step 1: Write the failing test**

Extend `buildTestZone` to add a delegation node `deleg2` (NS, no SOA) with a glue `A`, then:

```go
func TestWalkZoneAuthFlags(t *testing.T) {
	apex := newDataNode(nil, "example", "", false)
	apex.records["SOA"] = map[string]recordType{"": {content: "ns1 host 1 2 3 4 5"}}
	apex.records["NS"] = map[string]recordType{"": {content: "ns1.example."}} // apex NS → auth
	deleg := newDataNode(apex, "sub", ".", false)
	deleg.records["NS"] = map[string]recordType{"": {content: "ns1.sub.example."}} // delegation NS → non-auth
	deleg.records["A"] = map[string]recordType{"": {content: "192.0.2.50"}}         // glue → non-auth
	apex.children["sub"] = deleg

	var result []objectType[any]
	apex.RLock(false); apex.walkZoneRecords(4, &result); apex.RUnlock(false)

	authByContent := map[string]bool{}
	for _, it := range result { authByContent[it["content"].(string)] = it["auth"].(bool) }
	if authByContent["ns1.example."] != true { Errorf(t, "apex NS must be auth") }
	if authByContent["ns1.sub.example."] != false { Errorf(t, "delegation NS must be non-auth") }
	if authByContent["192.0.2.50"] != false { Errorf(t, "glue A must be non-auth") }
}
```

**Step 2: Run to verify it fails**

Run: `make unit-tests ONLY=TestWalkZoneAuthFlags`
Expected: FAIL (delegation NS/glue currently auth=true).

**Step 3: Write minimal implementation**

Change `walkZoneRecords` to track delegation and override `auth`:

```go
func (dn *dataNode) walkZoneRecords(pdnsVersion uint, result *[]objectType[any]) {
	dn.walkZoneRecordsAuth(pdnsVersion, false, result)
}

func (dn *dataNode) walkZoneRecordsAuth(pdnsVersion uint, belowDelegation bool, result *[]objectType[any]) {
	_, isDelegation := dn.records["NS"][""]
	isDelegation = isDelegation && !dn.hasSOA() // apex has NS+SOA and is authoritative
	qname := dn.getName()
	for qtype, byID := range dn.records {
		for _, record := range byID {
			record := record
			item := makeResultItem(qname, qtype, dn, &record, pdnsVersion)
			// non-auth: glue below a delegation, and the delegation's own NS records
			if belowDelegation || (isDelegation && qtype == "NS") || (isDelegation && (qtype == "A" || qtype == "AAAA")) {
				item["auth"] = false
			}
			*result = append(*result, item)
		}
	}
	childBelow := belowDelegation || isDelegation
	for _, child := range dn.children {
		child.RLock(false)
		if !child.hasSOA() {
			child.walkZoneRecordsAuth(pdnsVersion, childBelow, result)
		}
		child.RUnlock(false)
	}
}
```

> Note: this keeps `DS`/`NSEC`/`RRSIG` at the delegation point as `auth=1` (correct: DS is signed in the parent). Validate exact semantics against the F4 integration test with a validating secondary; refine if PowerDNS rejects any RRset.

**Step 4: Run to verify it passes**

Run: `make unit-tests ONLY='TestWalkZone'`
Expected: PASS (both walk tests).

**Step 5: Commit**

```bash
git add src/lookup.go src/lookup_test.go
git commit -m "feat: mark delegation NS and glue as non-auth in AXFR walk

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 14: Integration test — pre-signed DNSSEC AXFR

**Files:** Modify `src/integration_test.go` (`TestAXFRPresigned`).

**Approach:** Seed a small pre-signed zone into etcd (apex SOA with `X-PE3-FIXED-SERIAL` matching the baked `RRSIG(SOA)`, DNSKEY, RRSIGs, NSEC chain — reuse fixtures from the existing DNSSEC tests if present in `src/dnssec_test.go`/`testdata`). Set zone metadata `PRESIGNED=1`. AXFR via `dns.Transfer` and assert the envelope contains `*dns.DNSKEY` and `*dns.RRSIG` records and that the SOA serial equals the fixed serial. Run: `make integration-tests ONLY=TestAXFRPresigned VERBOSE=1`. Commit when green.

```bash
git commit -m "test: integration AXFR of a pre-signed DNSSEC zone

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## PHASE Transversal — versioning & docs

### Task 15: Bump dataVersion + document the on-etcd additions

**Why:** A new on-etcd key shape (`-tsig-/<name>`) was introduced ⇒ bump `dataVersion` and update docs + build workflow (CLAUDE.md rule).

**Files:**
- Modify: `src/data.go` (`dataVersion` Minor `0` → `1`)
- Modify: `doc/ETCD-structure.md`
- Modify: the build workflow that pins the data version (search `.github/workflows/` for the data-version value)

**Steps:**
1. `src/data.go`: `dataVersion = VersionType{IsDevelopment: true, Major: 2, Minor: 1}`.
2. `doc/ETCD-structure.md`: add sections for: `-tsig-/<keyname>` entries (`"<algorithm> <base64-secret>"`); the metadata keys that drive primary operation (`TSIG-ALLOW-AXFR`, `ALSO-NOTIFY`, `ALLOW-AXFR-FROM`, `PRESIGNED`); and that `X-PE3-NOTIFIED-SERIAL` is intentionally **not** stored (in-memory only). Document primary-mode requirements (standalone mode, `primary=yes`/`master=yes`, `also-notify`).
3. Update the workflow's expected data version.
4. Run full suite: `make unit-tests` (and at least `make integration-tests ONLY=TestAXFR`).

**Step 5: Commit**

```bash
git add src/data.go doc/ETCD-structure.md .github/
git commit -m "docs: bump dataVersion to 2.1 and document AXFR/TSIG/primary on-etcd shape

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 16: README — primary/secondary operation guide

**Files:** Modify `README.md`.
Document: enabling primary mode (PowerDNS `primary=yes` + connector), seeding a zone, adding a TSIG key + `TSIG-ALLOW-AXFR`, pointing an external secondary, and the standalone-mode requirement for NOTIFY (with the restart re-NOTIFY caveat). Commit.

```bash
git commit -m "docs: README guide for primary mode with an external secondary

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Final verification

- `make` (fmt + build + vet + golangci-lint + unit tests) — all green.
- `make integration-tests ONLY='TestAXFR|TestAXFRTSIG|TestAXFRPresigned' VERBOSE=1` — green.
- Manual smoke (optional): seed a zone, run pe3 standalone, `dig AXFR example.test. @<pdns>` and confirm SOA-bracketed records; with a TSIG key, `dig -y hmac-sha256:xfr.:<secret> AXFR ...`.

## Risk register / things the executor must watch

- **`cli.Get` signature** (Task 11): confirm against `src/etcd.go`; adjust channel/return handling.
- **JSON number type** for `id`/`serial` in `setNotified` (Task 8): `paramInt64` handles float64/json.Number/string.
- **`kind` value**: `"MASTER"` is accepted by all PowerDNS versions in the test matrix; only switch to `"PRIMARY"` if a version rejects it.
- **`master=yes` vs `primary=yes`** and **`getUpdatedMasters` vs `getUpdatedPrimaries`**: branch by PowerDNS version in tests; the dispatch already handles both method names.
- **auth semantics** for pre-signed delegations (Task 13): validate with the F4 integration test against a validating secondary; refine if any RRset is rejected.
- **NOTIFY requires standalone mode** (F2 preamble): in pipe mode each thread is a separate process, so the in-memory notified-serial/registry is not shared — document and, if desired, log a warning when primary methods are used in pipe mode.
