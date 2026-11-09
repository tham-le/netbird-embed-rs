package main

import "testing"

func TestParseJSONStringList(t *testing.T) {
	if got, err := parseJSONStringList(""); err != nil || got != nil {
		t.Fatalf("empty: got %v, %v", got, err)
	}
	got, err := parseJSONStringList(`["a","b"]`)
	if err != nil || len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("list: got %v, %v", got, err)
	}
	if _, err := parseJSONStringList(`{"a":1}`); err == nil {
		t.Fatal("expected error for non-array JSON")
	}
}

func TestOptBool(t *testing.T) {
	if optBool(-1) != nil {
		t.Fatal("-1 must be nil")
	}
	if v := optBool(0); v == nil || *v {
		t.Fatal("0 must be false")
	}
	if v := optBool(1); v == nil || !*v {
		t.Fatal("1 must be true")
	}
}

func TestOptUint16(t *testing.T) {
	if v, err := optUint16(-1); err != nil || v != nil {
		t.Fatalf("-1: got %v, %v", v, err)
	}
	if v, err := optUint16(1400); err != nil || v == nil || *v != 1400 {
		t.Fatalf("1400: got %v, %v", v, err)
	}
	if _, err := optUint16(70000); err == nil {
		t.Fatal("expected overflow error")
	}
}

func TestOptUint32(t *testing.T) {
	if v, err := optUint32(-1); err != nil || v != nil {
		t.Fatalf("-1: got %v, %v", v, err)
	}
	if v, err := optUint32(256); err != nil || v == nil || *v != 256 {
		t.Fatalf("256: got %v, %v", v, err)
	}
}
