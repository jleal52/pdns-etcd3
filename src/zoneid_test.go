//go:build unit

package src

import (
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
