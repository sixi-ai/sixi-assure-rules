//go:build linux

package rules

import (
	"runtime"
	"syscall"
	"time"
)

// rusageThread is RUSAGE_THREAD (linux/resource.h): the calling thread's usage only.
const rusageThread = 1

// threadCPUTime runs f on one locked OS thread and returns the CPU time (user + system) that thread spent in it, so
// a measurement does not depend on how loaded the machine is (other processes and the test binary's other goroutines
// are not counted). ok is false when the kernel refuses the query; the caller then measures wall time.
func threadCPUTime(f func()) (d time.Duration, ok bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var before, after syscall.Rusage
	if err := syscall.Getrusage(rusageThread, &before); err != nil {
		f()
		return 0, false
	}
	f()
	if err := syscall.Getrusage(rusageThread, &after); err != nil {
		return 0, false
	}
	used := func(r syscall.Rusage) time.Duration {
		return time.Duration(r.Utime.Nano() + r.Stime.Nano())
	}
	return used(after) - used(before), true
}
