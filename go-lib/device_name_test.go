package main

import (
	"context"
	"reflect"
	"testing"

	"github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/client/system"
)

func TestSystemInfoUsesDeviceName(t *testing.T) {
	ctx := context.WithValue(context.Background(), system.DeviceNameCtxKey, "rust")
	if got := system.GetInfo(ctx).Hostname; got != "rust" {
		t.Fatalf("hostname = %q, want rust", got)
	}
}

func TestEmbedKeepsDeviceName(t *testing.T) {
	c, err := embed.New(embed.Options{DeviceName: "rust", SetupKey: "dummy"})
	if err != nil {
		t.Fatal(err)
	}
	got := reflect.ValueOf(c).Elem().FieldByName("deviceName").String()
	if got != "rust" {
		t.Fatalf("deviceName = %q, want rust", got)
	}
}
