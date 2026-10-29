// Package cert parses the certificate format consumed by the hycert kernel.
//
// The certificate is untrusted input. Parsing is strict: an unknown line, a
// repeated section, or a malformed place is an error, never a default.
package cert

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Pos struct {
	Line int
	Col  int
}

func (p Pos) String() string { return fmt.Sprintf("%d:%d", p.Line, p.Col) }

// PlaceRef is a syntactic place before root lengths are known:
// "R2" (whole root) or "R2[1:3]" (element interval).
type PlaceRef struct {
	Root   string
	Lo     int
	Hi     int
	Ranged bool
}

type RootClaim struct {
	Name string
	Pos  Pos
	Len  int
}

type TaskClaim struct {
	Name   string
	Pos    Pos
	Callee string
}

type Step struct {
	Pos   Pos
	Kind  string
	Place PlaceRef
	From  string
	To    string
}

type Cert struct {
	Digest string
	Build  string
	Kernel string
	Roots  []RootClaim
	Tasks  []TaskClaim
	Steps  []Step
}

func ParseFile(path string) (*Cert, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	c := &Cert{}
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		f := strings.Fields(text)
		switch f[0] {
		case "hycert":
			if len(f) != 2 || f[1] != "v0" {
				return nil, fmt.Errorf("line %d: unsupported certificate version", line)
			}
		case "artifact":
			if len(f) != 3 || f[1] != "sha256" {
				return nil, fmt.Errorf("line %d: want `artifact sha256 <hex>`", line)
			}
			c.Digest = strings.ToLower(f[2])
		case "build":
			if len(f) != 2 {
				return nil, fmt.Errorf("line %d: want `build <key=value,...>`", line)
			}
			c.Build = f[1]
		case "kernel":
			if len(f) != 2 {
				return nil, fmt.Errorf("line %d: want `kernel <name>`", line)
			}
			c.Kernel = f[1]
		case "root":
			r, err := parseRoot(f, line)
			if err != nil {
				return nil, err
			}
			c.Roots = append(c.Roots, r)
		case "task":
			t, err := parseTask(f, line)
			if err != nil {
				return nil, err
			}
			c.Tasks = append(c.Tasks, t)
		case "step":
			s, err := parseStep(f, line)
			if err != nil {
				return nil, err
			}
			c.Steps = append(c.Steps, s)
		default:
			return nil, fmt.Errorf("line %d: unknown directive %q", line, f[0])
		}
		seen[f[0]] = true
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !seen["hycert"] {
		return nil, fmt.Errorf("missing `hycert v0` header")
	}
	for _, req := range []string{"artifact", "build", "kernel"} {
		if !seen[req] {
			return nil, fmt.Errorf("missing `%s` directive", req)
		}
	}
	return c, nil
}

func parseRoot(f []string, line int) (RootClaim, error) {
	if len(f) != 5 || f[3] != "len" {
		return RootClaim{}, fmt.Errorf("line %d: want `root <name> <line:col> len <n>`", line)
	}
	p, err := ParsePos(f[2])
	if err != nil {
		return RootClaim{}, fmt.Errorf("line %d: %v", line, err)
	}
	n, err := strconv.Atoi(f[4])
	if err != nil || n <= 0 {
		return RootClaim{}, fmt.Errorf("line %d: bad root length %q", line, f[4])
	}
	return RootClaim{Name: f[1], Pos: p, Len: n}, nil
}

func parseTask(f []string, line int) (TaskClaim, error) {
	if len(f) != 4 {
		return TaskClaim{}, fmt.Errorf("line %d: want `task <name> <line:col> <entry|spawn:callee>`", line)
	}
	p, err := ParsePos(f[2])
	if err != nil {
		return TaskClaim{}, fmt.Errorf("line %d: %v", line, err)
	}
	callee := f[3]
	if callee != "entry" {
		if !strings.HasPrefix(callee, "spawn:") {
			return TaskClaim{}, fmt.Errorf("line %d: task kind must be `entry` or `spawn:<callee>`", line)
		}
		callee = strings.TrimPrefix(callee, "spawn:")
	}
	return TaskClaim{Name: f[1], Pos: p, Callee: callee}, nil
}

func parseStep(f []string, line int) (Step, error) {
	if len(f) < 4 {
		return Step{}, fmt.Errorf("line %d: want `step <line:col> <kind> ...`", line)
	}
	p, err := ParsePos(f[1])
	if err != nil {
		return Step{}, fmt.Errorf("line %d: %v", line, err)
	}
	s := Step{Pos: p, Kind: f[2]}
	switch s.Kind {
	case "write", "read":
		if len(f) != 5 {
			return Step{}, fmt.Errorf("line %d: want `step <pos> %s <place> <task>`", line, s.Kind)
		}
		pl, err := ParsePlace(f[3])
		if err != nil {
			return Step{}, fmt.Errorf("line %d: %v", line, err)
		}
		s.Place, s.From = pl, f[4]
	case "transfer":
		if len(f) != 6 {
			return Step{}, fmt.Errorf("line %d: want `step <pos> transfer <place> <from> <to>`", line)
		}
		pl, err := ParsePlace(f[3])
		if err != nil {
			return Step{}, fmt.Errorf("line %d: %v", line, err)
		}
		s.Place, s.From, s.To = pl, f[4], f[5]
	case "join":
		if len(f) != 4 {
			return Step{}, fmt.Errorf("line %d: want `step <pos> join <task>`", line)
		}
		s.From = f[3]
	case "unshare", "share":
		return Step{}, fmt.Errorf("line %d: op %q is not in the v0 rule set", line, s.Kind)
	default:
		return Step{}, fmt.Errorf("line %d: unknown step kind %q", line, s.Kind)
	}
	return s, nil
}

func ParsePos(s string) (Pos, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return Pos{}, fmt.Errorf("bad position %q (want line:col)", s)
	}
	l, err := strconv.Atoi(parts[0])
	if err != nil || l <= 0 {
		return Pos{}, fmt.Errorf("bad line in position %q", s)
	}
	c, err := strconv.Atoi(parts[1])
	if err != nil || c <= 0 {
		return Pos{}, fmt.Errorf("bad column in position %q", s)
	}
	return Pos{Line: l, Col: c}, nil
}

// ParsePlace parses "R2" or "R2[1:3]".
func ParsePlace(s string) (PlaceRef, error) {
	open := strings.IndexByte(s, '[')
	if open < 0 {
		if s == "" {
			return PlaceRef{}, fmt.Errorf("empty place")
		}
		return PlaceRef{Root: s}, nil
	}
	if !strings.HasSuffix(s, "]") {
		return PlaceRef{}, fmt.Errorf("bad place %q", s)
	}
	root := s[:open]
	body := s[open+1 : len(s)-1]
	parts := strings.Split(body, ":")
	if len(parts) != 2 {
		return PlaceRef{}, fmt.Errorf("bad range in place %q", s)
	}
	lo, err1 := strconv.Atoi(parts[0])
	hi, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || lo < 0 || hi < lo {
		return PlaceRef{}, fmt.Errorf("bad range in place %q", s)
	}
	return PlaceRef{Root: root, Lo: lo, Hi: hi, Ranged: true}, nil
}
