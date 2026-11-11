package safego

import "testing"

func TestRecoverContainsPanic(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer Recover("test")
		panic("boom")
	}()
	<-done // reaching here (without the test binary dying) proves containment
}
