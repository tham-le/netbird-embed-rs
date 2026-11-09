package main

import (
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"
)

func TestWriteCStringZeroLength(t *testing.T) {
	testWriteCString("hello", nil, 0)
	testWriteCString("hello", nil, 8)

	// A zero length must leave the buffer completely untouched.
	const size = 8
	untouched := testAlloc(size)
	defer testFree(untouched)
	fill := unsafe.Slice((*byte)(untouched), size)
	for i := range fill {
		fill[i] = 0xAA
	}
	testWriteCString("hello", untouched, 0)
	for i, b := range fill {
		if b != 0xAA {
			t.Fatalf("buf_len 0 wrote byte %d = %#x", i, b)
		}
	}

	// A one-byte buffer only fits the terminator.
	one := testAllocZeroed(1)
	defer testFree(one)
	testWriteCString("hello", one, 1)
	if got := testGoString(one); got != "" {
		t.Fatalf("buf_len 1 wrote %q", got)
	}

	full := testAllocZeroed(8)
	defer testFree(full)
	testWriteCString("hello", full, 8)
	if got := testGoString(full); got != "hello" {
		t.Fatalf("buf_len 8 wrote %q", got)
	}
}

func TestWriteJSONNullBuffer(t *testing.T) {
	if got := testWriteJSON([]byte("{}"), nil, 16); got != testERANGE() {
		t.Fatalf("writeJSON(nil) = %d, want ERANGE", got)
	}
	if got := testWriteJSON([]byte("{}"), nil, 0); got != testERANGE() {
		t.Fatalf("writeJSON(nil, 0) = %d, want ERANGE", got)
	}
}

func TestAllocHandleWrapsPositive(t *testing.T) {
	handleMu.Lock()
	oldID, oldClients := nextID, clients
	clients = testEmptyClients()
	nextID = math.MaxInt32
	handle := allocHandle()
	wrapped := nextID
	handleMu.Unlock()

	clients, nextID = oldClients, oldID

	if handle != math.MaxInt32 {
		t.Fatalf("handle = %d, want %d", handle, math.MaxInt32)
	}
	if wrapped != 1 {
		t.Fatalf("nextID = %d, want 1 after wrap", wrapped)
	}
}

func TestAllocCaptureIDWraps(t *testing.T) {
	old := captureIDCounter
	defer func() { captureIDCounter = old }()

	captureIDCounter = math.MaxInt32
	if got := allocCaptureID(); got != 1 {
		t.Fatalf("allocCaptureID after wrap = %d, want 1", got)
	}
}

func TestOptUint16RejectsOutOfRange(t *testing.T) {
	if v, err := optUint16(-1); err != nil || v != nil {
		t.Fatalf("optUint16(-1) = %v, %v", v, err)
	}
	if _, err := optUint16(65536); err == nil {
		t.Fatal("optUint16(65536) accepted")
	}
	if v, err := optUint16(65535); err != nil || v == nil || *v != 65535 {
		t.Fatalf("optUint16(65535) = %v, %v", v, err)
	}
}

func TestOpenCaptureFileIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcap")
	f, err := openCaptureFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("mode = %o, want 600", mode)
		}
	}
}

func TestOpenCaptureFileRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("openNoFollow is a no-op on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openCaptureFile(link); err == nil {
		t.Fatal("openCaptureFile followed a symlink")
	}
}

type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

func TestListenPort(t *testing.T) {
	if got := listenPort(stringAddr("10.0.0.1:7777"), 80); got != 7777 {
		t.Fatalf("listenPort = %d, want 7777", got)
	}
	if got := listenPort(stringAddr(""), 80); got != 80 {
		t.Fatalf("listenPort fallback = %d, want 80", got)
	}
}

var _ = unsafe.Pointer(nil)
