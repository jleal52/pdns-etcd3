/* Copyright 2016-2026 nix <https://keybase.io/nixn>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

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
