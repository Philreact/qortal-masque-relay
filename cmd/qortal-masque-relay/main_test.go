package main

import (
	"reflect"
	"testing"
)

func TestTargetListAcceptsRepeatedAndCommaSeparatedValues(t *testing.T) {
	var targets targetList
	for _, value := range []string{"127.0.0.1:9000, 192.0.2.10:9001", "[2001:db8::10]:9002"} {
		if err := targets.Set(value); err != nil {
			t.Fatal(err)
		}
	}
	want := targetList{"127.0.0.1:9000", "192.0.2.10:9001", "[2001:db8::10]:9002"}
	if !reflect.DeepEqual(targets, want) {
		t.Fatalf("targets = %#v, want %#v", targets, want)
	}
}

func TestTargetListIgnoresEmptyValues(t *testing.T) {
	var targets targetList
	if err := targets.Set(" , "); err != nil {
		t.Fatal(err)
	}
	if len(targets) != 0 {
		t.Fatalf("targets = %#v, want empty", targets)
	}
}
