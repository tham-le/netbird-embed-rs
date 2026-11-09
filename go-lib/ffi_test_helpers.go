package main

/*
#include <stdlib.h>
#include <errno.h>
*/
import "C"

import "unsafe"

// Tiny cgo shims so _test.go files can stay free of `import "C"` (which the
// go test tool does not support for this package).

func testAlloc(n int) unsafe.Pointer { return C.malloc(C.size_t(n)) }

// testAllocZeroed returns zero-initialized memory so C.GoString on a buffer
// that was never written still terminates.
func testAllocZeroed(n int) unsafe.Pointer { return C.calloc(C.size_t(n), 1) }

func testFree(p unsafe.Pointer) { C.free(p) }

func testGoString(p unsafe.Pointer) string { return C.GoString((*C.char)(p)) }

func testWriteCString(msg string, p unsafe.Pointer, n int) {
	writeCString(msg, (*C.char)(p), C.int(n))
}

func testWriteJSON(data []byte, p unsafe.Pointer, n int) int {
	return int(writeJSON(data, (*C.char)(p), C.int(n)))
}

func testERANGE() int { return int(C.ERANGE) }

func testEmptyClients() map[C.int]*clientState { return make(map[C.int]*clientState) }
