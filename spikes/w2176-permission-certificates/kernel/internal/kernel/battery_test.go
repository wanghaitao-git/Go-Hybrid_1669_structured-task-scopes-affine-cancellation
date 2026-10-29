package kernel_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hycert/internal/artifact"
	"hycert/internal/cert"
	"hycert/internal/kernel"
)

// TestFalsifierBattery runs the pre-registered cases from RESULTS.md §4.
// Every expectation is stated before the run and nothing here is weakened to
// match the implementation.
func TestFalsifierBattery(t *testing.T) {
	cases := []struct {
		dir    string
		want   kernel.Verdict
		reason string
		why    string
	}{
		{"p01-accept", kernel.Accept, "", "P1 supported spawn, unique transfer, one join"},
		{"p02-disjoint-accept", kernel.Accept, "", "P2 disjoint split of one root across two tasks"},
		{"p03-surviving-alias", kernel.Reject, "without permission", "P3 surviving alias write after transfer"},
		{"p04-no-cert", kernel.NoCert, "no certificate", "P4 emitted Go with no derivation"},
		{"p05-overlap", kernel.Reject, "without holding it", "P5 overlapping concurrent transfers"},
		{"p06-forged-fresh", kernel.Reject, "root inventory contradicts", "P6 alias declared as a fresh allocation"},
		{"p07-omitted-op", kernel.Reject, "uncovered memory operation", "P7 a real write with no step"},
		{"p08-fabricated-step", kernel.Reject, "no such operation", "P8 a step at a position with no operation"},
		{"p09-live-element-write", kernel.Reject, "without permission", "P9 element write through a live binding"},
		{"p10-loop-no-cert", kernel.NoCert, "outside the certified subset", "P10 a loop"},
		{"p11-changed-artifact", kernel.NoCert, "digest mismatch", "P11 certificate bound to another artifact"},
		{"p12-missing-join", kernel.NoCert, "incomplete", "P12 derivation with no join assertion"},
		{"p13-wrong-but-safe", kernel.Accept, "", "P13 race-free but functionally wrong"},
		{"p14-unsupported-racy", kernel.NoCert, "outside the certified subset", "P14 racy program outside the subset"},
		{"p15-omitted-new-op", kernel.Reject, "uncovered memory operation", "P15 fresh digest, operation the derivation omits"},
	}

	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			dir := filepath.Join("..", "..", "testdata", tc.dir)
			prog, err := artifact.Load(filepath.Join(dir, "artifact.go"))
			if err != nil {
				t.Fatalf("%s: %v", tc.why, err)
			}
			model := prog.Build()

			var c *cert.Cert
			if _, err := os.Stat(filepath.Join(dir, "cert.txt")); err == nil {
				c, err = cert.ParseFile(filepath.Join(dir, "cert.txt"))
				if err != nil {
					t.Fatalf("%s: %v", tc.why, err)
				}
			} else {
				c = &cert.Cert{}
			}

			res := kernel.Verify(model, c)
			if res.Verdict != tc.want {
				t.Fatalf("%s: verdict %s, want %s (%v)", tc.why, res.Verdict, tc.want, res.Reasons)
			}
			if tc.reason != "" {
				joined := strings.Join(res.Reasons, " | ")
				if !strings.Contains(joined, tc.reason) {
					t.Fatalf("%s: reasons %q do not mention %q", tc.why, joined, tc.reason)
				}
			}
		})
	}
}

// TestNoCertificateForUnsupported claims the fail-closed direction: an
// artifact outside the subset can never be accepted, whatever it carries.
func TestNoCertificateForUnsupported(t *testing.T) {
	for _, dir := range []string{"p10-loop-no-cert", "p14-unsupported-racy"} {
		prog, err := artifact.Load(filepath.Join("..", "..", "testdata", dir, "artifact.go"))
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		model := prog.Build()
		res := kernel.Verify(model, &cert.Cert{})
		if res.Verdict == kernel.Accept {
			t.Fatalf("%s: unsupported artifact read as accepted", dir)
		}
	}
}

// TestCertificateIsCheckedAgainstText confirms that a derivation which is
// internally consistent but contradicts the Go text is rejected on the text.
func TestCertificateIsCheckedAgainstText(t *testing.T) {
	prog, err := artifact.Load(filepath.Join("..", "..", "testdata", "p01-accept", "artifact.go"))
	if err != nil {
		t.Fatal(err)
	}
	model := prog.Build()
	c, err := cert.ParseFile(filepath.Join("..", "..", "testdata", "p01-accept", "cert.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if res := kernel.Verify(model, c); res.Verdict != kernel.Accept {
		t.Fatalf("baseline certificate is not accepted: %v", res.Reasons)
	}

	forged := *c
	forged.Steps = append([]cert.Step(nil), c.Steps...)
	for i := range forged.Steps {
		if forged.Steps[i].Kind == "transfer" {
			forged.Steps[i].Place = cert.PlaceRef{Root: "R9"}
		}
	}
	if res := kernel.Verify(model, &forged); res.Verdict == kernel.Accept {
		t.Fatal("a transfer naming a root that does not exist was accepted")
	}
}
