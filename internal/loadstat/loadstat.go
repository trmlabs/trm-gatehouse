//go:build loadtest

package loadstat

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Budget skips a level whose sockets would pass LOADTEST_MAX_SOCKETS (default 2000), counting every end of every connection.
func Budget(t testing.TB, sessions, socketsPerSession int) {
	t.Helper()
	limit := Int(t, "LOADTEST_MAX_SOCKETS", 2000)
	if sessions*socketsPerSession > limit {
		t.Skipf("%d sessions need about %d sockets, over LOADTEST_MAX_SOCKETS=%d", sessions, sessions*socketsPerSession, limit)
	}
}

// Levels reads LOADTEST_LEVELS, a comma list of concurrent session counts.
func Levels(t testing.TB) []int {
	t.Helper()
	raw := os.Getenv("LOADTEST_LEVELS")
	if raw == "" {
		raw = "100,500,1000,10000"
	}
	var out []int
	for _, f := range strings.Split(raw, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 1 {
			t.Fatalf("LOADTEST_LEVELS entry %q is not a positive integer", f)
		}
		out = append(out, n)
	}
	return out
}

// Int reads a positive integer setting, or def when unset.
func Int(t testing.TB, name string, def int) int {
	t.Helper()
	raw := os.Getenv(name)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		t.Fatalf("%s must be a positive integer, got %q", name, raw)
	}
	return n
}

// RaiseFDLimit lifts the soft descriptor limit as far as the hard limit allows and returns the limit in force.
func RaiseFDLimit() uint64 {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return 0
	}
	for _, want := range []uint64{1 << 20, 1 << 17, 90000} {
		if lim.Cur >= want {
			break
		}
		next := lim
		next.Cur = min(want, lim.Max)
		if syscall.Setrlimit(syscall.RLIMIT_NOFILE, &next) == nil {
			lim = next
			break
		}
	}
	_ = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
	return uint64(lim.Cur)
}

// Snapshot is the process's resource use at one instant.
type Snapshot struct {
	Heap, Stack uint64
	Goroutines  int
	FDs         int
}

// Take collects garbage and reads the process's resource use.
func Take() Snapshot {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return Snapshot{Heap: m.HeapInuse, Stack: m.StackInuse, Goroutines: runtime.NumGoroutine(), FDs: OpenFDs()}
}

// OpenFDs counts this process's open descriptors, or -1 if it cannot.
func OpenFDs() int {
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		if entries, err := os.ReadDir(dir); err == nil {
			return len(entries)
		}
	}
	return -1
}

// Delta is the growth between two snapshots.
func (s Snapshot) Delta(base Snapshot) Snapshot {
	return Snapshot{Heap: sub(s.Heap, base.Heap), Stack: sub(s.Stack, base.Stack), Goroutines: s.Goroutines - base.Goroutines, FDs: s.FDs - base.FDs}
}

func sub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

// Percentiles sorts d and returns its p50, p99 and maximum.
func Percentiles(d []time.Duration) (p50, p99, maxd time.Duration) {
	if len(d) == 0 {
		return 0, 0, 0
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	at := func(p float64) time.Duration {
		i := int(p * float64(len(d)-1))
		return d[i]
	}
	return at(0.50), at(0.99), d[len(d)-1]
}

// Row prints one result line that the plan's table is built from.
func Row(fields ...any) {
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		parts = append(parts, fmt.Sprint(f))
	}
	fmt.Println("LOADTEST|" + strings.Join(parts, "|"))
}

// Profile records CPU, mutex and blocking profiles into LOADTEST_PROFILE_DIR until the returned function runs; unset, it does nothing.
func Profile(t testing.TB, label string) func() {
	t.Helper()
	dir := os.Getenv("LOADTEST_PROFILE_DIR")
	if dir == "" {
		return func() {}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil { //nolint:gosec // operator-set output directory
		t.Fatalf("profile dir: %v", err)
	}
	cpu, err := os.Create(dir + "/" + label + ".cpu.pprof") //nolint:gosec // operator-set output directory
	if err != nil {
		t.Fatalf("cpu profile: %v", err)
	}
	if err := pprof.StartCPUProfile(cpu); err != nil {
		t.Fatalf("cpu profile: %v", err)
	}
	runtime.SetMutexProfileFraction(5)
	runtime.SetBlockProfileRate(int((time.Millisecond).Nanoseconds()))
	return func() {
		pprof.StopCPUProfile()
		_ = cpu.Close()
		for _, name := range []string{"mutex", "block"} {
			if f, err := os.Create(dir + "/" + label + "." + name + ".pprof"); err == nil { //nolint:gosec // operator-set output directory
				_ = pprof.Lookup(name).WriteTo(f, 0)
				_ = f.Close()
			}
		}
		runtime.SetMutexProfileFraction(0)
		runtime.SetBlockProfileRate(0)
	}
}
