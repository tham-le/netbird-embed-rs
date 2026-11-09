package main

import "testing"

func TestPreallocEnabled(t *testing.T) {
	if preallocEnabled(nil) {
		t.Fatal("nil must be disabled")
	}
	zero := uint32(0)
	if preallocEnabled(&zero) {
		t.Fatal("zero must be disabled")
	}
	nonzero := uint32(1)
	if !preallocEnabled(&nonzero) {
		t.Fatal("nonzero must be enabled")
	}
}
