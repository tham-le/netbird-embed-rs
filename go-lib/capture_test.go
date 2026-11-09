package main

import "testing"

func TestParseCaptureOptions(t *testing.T) {
	opts, err := parseCaptureOptions(`{"pcap_path":"/tmp/a.pcap","text_path":"/tmp/a.txt","filter":"tcp port 443","verbose":true,"ascii":true}`)
	if err != nil {
		t.Fatal(err)
	}
	if opts.PcapPath != "/tmp/a.pcap" || opts.TextPath != "/tmp/a.txt" {
		t.Fatalf("unexpected options: %+v", opts)
	}
	if opts.Filter != "tcp port 443" || !opts.Verbose || !opts.ASCII {
		t.Fatalf("unexpected options: %+v", opts)
	}
}

func TestAllocCaptureIDIsMonotonic(t *testing.T) {
	a := allocCaptureID()
	b := allocCaptureID()
	if b <= a {
		t.Fatalf("ids must increase: %d then %d", a, b)
	}
}
