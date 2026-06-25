package approver

import (
	"fmt"
	"sort"
)

// registry holds approver constructors keyed by name. Approvers add themselves
// from init() in build-tag-guarded packages, blank-imported by the binary, so a
// build ships only the approvers it wants compiled in (ADR 0004).
var registry = map[string]func() Approver{}

// Register adds a named approver constructor. It panics on a duplicate name,
// since that is a build-wiring error, not a runtime condition.
func Register(name string, ctor func() Approver) {
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("approver: duplicate registration %q", name))
	}
	registry[name] = ctor
}

// New constructs a fresh instance of the named approver, or an error if no such
// approver is compiled in.
func New(name string) (Approver, error) {
	ctor, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("approver %q is not compiled in", name)
	}
	return ctor(), nil
}

// Registered returns the names of all compiled-in approvers, sorted.
func Registered() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
