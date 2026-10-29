package kernel_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hycert/internal/artifact"
	"hycert/internal/cert"
	"hycert/internal/kernel"
)

// TestScaling logs the cost of a verified artifact as it grows. It asserts
// only the shape that matters (one derivation step per operation and a
// verdict of ACCEPT); the timings are recorded for the RESULTS log rather than
// asserted, because wall-clock assertions are how test suites start lying.
func TestScaling(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []int{50, 100, 200, 400, 800} {
		src := filepath.Join(dir, fmt.Sprintf("artifact_%d.go", n))
		var b strings.Builder
		fmt.Fprintf(&b, "package main\n\nfunc main() {\n\tx := make([]int, %d)\n", n)
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "\tx[%d] = %d\n", i, i)
		}
		b.WriteString("}\n")
		if err := os.WriteFile(src, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}

		prog, err := artifact.Load(src)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		model := prog.Build()

		dump := filepath.Join(dir, fmt.Sprintf("cert_%d.txt", n))
		if err := os.WriteFile(dump, []byte(kernel.Dump(model)), 0o644); err != nil {
			t.Fatal(err)
		}
		c, err := cert.ParseFile(dump)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}

		start := time.Now()
		res := kernel.Verify(model, c)
		elapsed := time.Since(start)
		if res.Verdict != kernel.Accept {
			t.Fatalf("n=%d: %s %v", n, res.Verdict, res.Reasons)
		}
		if res.Steps != n {
			t.Fatalf("n=%d: %d steps for %d operations", n, res.Steps, n)
		}
		t.Logf("n=%-4d events=%-4d steps=%-4d wall=%v", n, res.Events, res.Steps, elapsed)
	}
}
