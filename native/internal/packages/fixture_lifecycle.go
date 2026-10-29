//go:build onecontrol_lifecycle_fixture

package packages

func OpenLifecycleFixture(o Options) (*Delivery, error) { return open(o, true) }
