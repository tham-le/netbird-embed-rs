package main

import (
	"testing"

	"github.com/netbirdio/netbird/client/embed"
)

func TestParseExposeRequest(t *testing.T) {
	req, err := parseExposeRequest(`{"name_prefix":"api","port":8080,"protocol":"https","user_groups":["g1"],"listen_port":9000}`)
	if err != nil {
		t.Fatal(err)
	}
	if req.NamePrefix != "api" || req.Port != 8080 || req.Protocol != embed.ExposeProtocolHTTPS {
		t.Fatalf("unexpected request: %+v", req)
	}
	if req.ListenPort != 9000 || len(req.UserGroups) != 1 || req.UserGroups[0] != "g1" {
		t.Fatalf("unexpected request: %+v", req)
	}
}

func TestExposeProtocol(t *testing.T) {
	cases := map[string]embed.ExposeProtocolType{
		"":      embed.ExposeProtocolHTTP,
		"http":  embed.ExposeProtocolHTTP,
		"https": embed.ExposeProtocolHTTPS,
		"tcp":   embed.ExposeProtocolTCP,
		"udp":   embed.ExposeProtocolUDP,
		"tls":   embed.ExposeProtocolTLS,
	}
	for in, want := range cases {
		got, err := exposeProtocol(in)
		if err != nil || got != want {
			t.Fatalf("%q: got %v, %v", in, got, err)
		}
	}
	if _, err := exposeProtocol("smtp"); err == nil {
		t.Fatal("expected error for unknown protocol")
	}
}

func TestAddExposeRejectsDuplicateDomain(t *testing.T) {
	cs := &clientState{}
	first := &exposeEntry{}
	if err := cs.addExpose("svc.example", first); err != nil {
		t.Fatal(err)
	}
	if err := cs.addExpose("svc.example", &exposeEntry{}); err == nil {
		t.Fatal("expected duplicate error")
	}
}

func TestFindExposeMatchesCallIDOnly(t *testing.T) {
	cs := &clientState{}
	e := &exposeEntry{callID: "call-1", response: []byte(`{"domain":"svc.example"}`)}
	if err := cs.addExpose("svc.example", e); err != nil {
		t.Fatal(err)
	}
	if got := cs.findExpose("call-1"); string(got) != `{"domain":"svc.example"}` {
		t.Fatalf("expected cached response, got %q", got)
	}
	if got := cs.findExpose("call-2"); got != nil {
		t.Fatalf("different call id must miss, got %q", got)
	}
}

func TestFindExposeMissesAfterRemoval(t *testing.T) {
	cs := &clientState{}
	e := &exposeEntry{callID: "call-1", response: []byte(`{}`)}
	if err := cs.addExpose("svc.example", e); err != nil {
		t.Fatal(err)
	}
	cs.removeExpose("svc.example", e)
	if got := cs.findExpose("call-1"); got != nil {
		t.Fatalf("removed session must miss, got %q", got)
	}
}
