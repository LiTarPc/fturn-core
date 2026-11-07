package turndial

import (
	"errors"
	"testing"
)

func TestRenewalWatchTypedFailuresAndIndependentSuccess(t *testing.T) {
	var got []error
	w := &renewalWatch{onDead: func(e error) { got = append(got, e) }}
	err := errors.New("typed renewal error")
	w.result(false, err)
	w.result(true, err)
	if len(got) != 0 {
		t.Fatal("unrelated stages combined")
	}
	w.result(false, nil)
	w.result(false, err)
	if len(got) != 0 {
		t.Fatal("success did not reset failures")
	}
	w.result(false, err)
	if len(got) != 1 || !errors.Is(got[0], err) {
		t.Fatalf("causes=%v", got)
	}
	w.result(true, err)
	if len(got) != 1 {
		t.Fatal("duplicate death event")
	}
}
