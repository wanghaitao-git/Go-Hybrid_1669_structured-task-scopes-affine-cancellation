// Command hycert replays a candidate permission derivation against an
// emitted Go artifact.
//
//	hycert verify -src artifact.go -cert artifact.cert
//
// Exit status: 0 ACCEPT, 1 REJECT, 2 NO-CERT.
package main

import (
	"flag"
	"fmt"
	"os"

	"hycert/internal/artifact"
	"hycert/internal/cert"
	"hycert/internal/kernel"
)

func main() {
	src := flag.String("src", "", "path to the Go artifact")
	certPath := flag.String("cert", "", "path to the certificate (omit to ask for none)")
	dump := flag.Bool("dump", false, "print the candidate derivation the kernel would require (producer helper, untrusted)")
	flag.Parse()
	if *src == "" {
		fmt.Fprintln(os.Stderr, "hycert: -src is required")
		os.Exit(2)
	}

	prog, err := artifact.Load(*src)
	if err != nil {
		fmt.Printf("NO-CERT\ndismissed because the artifact does not type-check as Go: %v\n", err)
		os.Exit(2)
	}
	model := prog.Build()

	if *dump {
		fmt.Print(kernel.Dump(model))
		return
	}

	c, err := loadCert(*certPath)
	if err != nil {
		fmt.Printf("NO-CERT\n%s\n", err)
		os.Exit(2)
	}

	res := kernel.Verify(model, c)
	fmt.Printf("%s\n", res.Verdict)
	for _, reason := range res.Reasons {
		fmt.Printf("- %s\n", reason)
	}
	if res.Verdict == kernel.Accept {
		fmt.Printf("checked %d events against %d derivation steps; artifact sha256 %s\n", res.Events, res.Steps, shortDigest(prog.Digest))
	}
	switch res.Verdict {
	case kernel.Accept:
		os.Exit(0)
	case kernel.Reject:
		os.Exit(1)
	default:
		os.Exit(2)
	}
}

func loadCert(path string) (*cert.Cert, error) {
	if path == "" {
		return nil, fmt.Errorf("no certificate supplied")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("no certificate supplied: %v", err)
	}
	return cert.ParseFile(path)
}

func shortDigest(d string) string {
	if len(d) > 16 {
		return d[:16]
	}
	return d
}
