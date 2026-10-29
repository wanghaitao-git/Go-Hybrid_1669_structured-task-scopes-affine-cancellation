// Package kernel replays a candidate permission derivation against the
// artifact model. It never asks the producer whether something is safe: the
// producer supplies decisions (who holds which place when), and every
// decision is checked against storage identity recomputed from the Go text.
package kernel

import (
	"fmt"
	"strconv"
	"strings"

	"hycert/internal/artifact"
	"hycert/internal/cert"
)

type Verdict int

const (
	Accept Verdict = iota
	Reject
	NoCert
)

func (v Verdict) String() string {
	switch v {
	case Accept:
		return "ACCEPT"
	case Reject:
		return "REJECT"
	}
	return "NO-CERT"
}

type Result struct {
	Verdict Verdict
	Reasons []string
	Events  int
	Steps   int
}

const KernelVersion = "hycert-v0"

type obligation struct {
	task  string
	pos   string
	kind  string
	place string
	to    string
	ev    artifact.Event
}

func obligationsOf(m *artifact.Model) ([]obligation, []obligation) {
	var ops, joins []obligation
	for _, ev := range m.Events {
		o := obligation{
			task:  ev.Task,
			pos:   m.Prog.Pos(ev.Pos),
			kind:  ev.Kind.String(),
			place: ev.Place.String(),
			to:    ev.To,
			ev:    ev,
		}
		switch ev.Kind {
		case artifact.EvJoin:
			o.task = ev.To
			joins = append(joins, o)
		case artifact.EvAlloc:
		default:
			ops = append(ops, o)
		}
	}
	return ops, joins
}

func Verify(m *artifact.Model, c *cert.Cert) Result {
	r := Result{Events: len(m.Events)}

	if m.Limit != "" {
		return noCert(r, "artifact is outside the certified subset: "+m.Limit)
	}
	if len(m.Broken) > 0 {
		return reject(r, m.Broken...)
	}
	if c == nil || c.Digest == "" {
		return noCert(r, "no certificate supplied")
	}
	if c.Digest != m.Prog.Digest {
		return noCert(r, fmt.Sprintf("artifact digest mismatch: certificate binds %s, artifact is %s", short(c.Digest), short(m.Prog.Digest)))
	}
	if c.Kernel != KernelVersion {
		return noCert(r, fmt.Sprintf("certificate is bound to kernel %q, this kernel is %q", c.Kernel, KernelVersion))
	}
	if why := checkBuildLine(c.Build); why != "" {
		return noCert(r, why)
	}

	if reasons := checkInventory(m, c); len(reasons) > 0 {
		return reject(r, reasons...)
	}

	ops, joins := obligationsOf(m)
	r.Events = len(m.Events)

	seen := make(map[string]int, len(ops))
	for _, o := range ops {
		seen[obKey(o.task, o.pos, o.kind, o.place)]++
	}
	joinSeen := make(map[string]int, len(joins))
	for _, o := range joins {
		joinSeen[obKey(o.task, o.pos, "join", "")]++
	}

	var reasons []string
	for _, s := range c.Steps {
		r.Steps++
		pos := s.Pos.String()
		if s.Kind == "join" {
			key := obKey(s.From, pos, "join", "")
			if joinSeen[key] == 0 {
				reasons = append(reasons, fmt.Sprintf("%s: join assertion for %s is not a join point in the artifact", pos, s.From))
				continue
			}
			joinSeen[key]--
			continue
		}
		key := obKey(s.From, pos, s.Kind, placeKey(m, s.Place))
		if seen[key] == 0 {
			reasons = append(reasons, fmt.Sprintf("%s: %s step names a place or task with no such operation in the artifact", pos, s.Kind))
			continue
		}
		seen[key]--
	}
	for key, n := range seen {
		if n > 0 {
			reasons = append(reasons, fmt.Sprintf("uncovered memory operation (%d left): %s", n, prettyKey(key)))
		}
	}
	for key, n := range joinSeen {
		if n > 0 {
			return noCert(r, fmt.Sprintf("derivation is incomplete: %d join assertion(s) missing (%s)", n, strings.TrimSpace(prettyKey(key))))
		}
	}
	if len(reasons) > 0 {
		return reject(r, reasons...)
	}

	if reasons := replay(m, c); len(reasons) > 0 {
		return reject(r, reasons...)
	}
	r.Verdict = Accept
	return r
}

func (r Result) with(reasons ...string) Result {
	r.Reasons = append(r.Reasons, reasons...)
	if len(r.Reasons) > 12 {
		r.Reasons = r.Reasons[:12]
	}
	return r
}

func noCert(r Result, reasons ...string) Result {
	r.Verdict = NoCert
	return r.with(reasons...)
}

func reject(r Result, reasons ...string) Result {
	r.Verdict = Reject
	return r.with(reasons...)
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}

func obKey(task, pos, kind, place string) string {
	return task + "|" + pos + "|" + kind + "|" + place
}

func prettyKey(k string) string {
	return strings.ReplaceAll(k, "|", " ")
}

// placeKey resolves a certificate place against the artifact's roots. A root
// name that does not exist resolves to a key no obligation can match, so a
// forged label is rejected on the text rather than trusted.
func placeKey(m *artifact.Model, p cert.PlaceRef) string {
	idx, ok := rootIndex(m, p.Root)
	if !ok {
		return "?" + p.Root
	}
	lo, hi := 0, m.Prog.Roots[idx-1].Len
	if p.Ranged {
		lo, hi = p.Lo, p.Hi
	}
	return artifact.Place{Root: idx, Lo: lo, Hi: hi}.String()
}

func rootIndex(m *artifact.Model, name string) (int, bool) {
	if !strings.HasPrefix(name, "R") {
		return 0, false
	}
	n, err := strconv.Atoi(name[1:])
	if err != nil || n < 1 || n > len(m.Prog.Roots) {
		return 0, false
	}
	return n, true
}

// checkInventory requires the certificate's root and task inventory to equal
// the one recomputed from the artifact. A producer that miscounts storage
// sites is contradicted here, not accommodated.
func checkInventory(m *artifact.Model, c *cert.Cert) []string {
	var reasons []string
	if len(c.Roots) != len(m.Prog.Roots) {
		reasons = append(reasons, fmt.Sprintf("root inventory contradicts the artifact: certificate declares %d, artifact has %d allocation sites", len(c.Roots), len(m.Prog.Roots)))
	}
	for i, rc := range c.Roots {
		if i >= len(m.Prog.Roots) {
			break
		}
		want := m.Prog.Roots[i]
		if rc.Name != fmt.Sprintf("R%d", want.ID) {
			reasons = append(reasons, fmt.Sprintf("root %d is named %q; the kernel's canonical name is R%d", i+1, rc.Name, want.ID))
			continue
		}
		if rc.Pos.String() != m.Prog.Pos(want.Pos) {
			reasons = append(reasons, fmt.Sprintf("root %s claims allocation at %s; the artifact allocates at %s", rc.Name, rc.Pos, m.Prog.Pos(want.Pos)))
		}
		if rc.Len != want.Len {
			reasons = append(reasons, fmt.Sprintf("root %s claims length %d; the artifact allocates %d", rc.Name, rc.Len, want.Len))
		}
	}

	if len(c.Tasks) != len(m.Tasks) {
		reasons = append(reasons, fmt.Sprintf("task inventory contradicts the artifact: certificate declares %d tasks, artifact has %d", len(c.Tasks), len(m.Tasks)))
	}
	for _, canon := range m.Tasks {
		found := false
		for _, tc := range c.Tasks {
			if tc.Name != canon {
				continue
			}
			found = true
			if tc.Pos.String() != m.Prog.Pos(m.TaskPos[canon]) {
				reasons = append(reasons, fmt.Sprintf("task %s claims spawn at %s; the artifact spawns at %s", canon, tc.Pos, m.Prog.Pos(m.TaskPos[canon])))
			}
			if tc.Callee != m.TaskCallee[canon] {
				reasons = append(reasons, fmt.Sprintf("task %s claims callee %q; the artifact spawns %q", canon, tc.Callee, m.TaskCallee[canon]))
			}
		}
		if !found {
			reasons = append(reasons, fmt.Sprintf("task %s is missing from the certificate", canon))
		}
	}
	return reasons
}

func checkBuildLine(b string) string {
	keys := map[string]bool{}
	for _, kv := range strings.Split(b, ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 || parts[0] == "" {
			return fmt.Sprintf("malformed build claim %q", b)
		}
		keys[parts[0]] = true
	}
	for _, req := range []string{"goos", "goarch", "goversion", "tags"} {
		if !keys[req] {
			return fmt.Sprintf("build claim does not bind %q: %q", req, b)
		}
	}
	return ""
}

// replay applies the derivation in artifact order. Ownership is exclusive by
// construction: a transfer splits a held segment, so two live tasks can never
// hold overlapping storage, and a write is legal only inside a segment the
// executing task holds.
func replay(m *artifact.Model, c *cert.Cert) []string {
	var st state
	var reasons []string
	for _, ev := range m.Events {
		switch ev.Kind {
		case artifact.EvAlloc:
			st.add(ev.Place, ev.Task)
		case artifact.EvRead, artifact.EvWrite:
			if !st.holds(ev.Task, ev.Place) {
				reasons = append(reasons, fmt.Sprintf("%s: %s %s by %s without permission on the overlapping storage", m.Prog.Pos(ev.Pos), ev.Kind, ev.Place, ev.Task))
			}
		case artifact.EvTransfer:
			if !st.take(ev.Task, ev.Place, ev.To) {
				reasons = append(reasons, fmt.Sprintf("%s: transfer %s from %s to %s without holding it (surviving alias write, or overlapping concurrent transfer)", m.Prog.Pos(ev.Pos), ev.Place, ev.Task, ev.To))
			}
		case artifact.EvJoin:
			if m.TaskCallee[ev.To] == "" {
				reasons = append(reasons, fmt.Sprintf("%s: join of unknown task %s", m.Prog.Pos(ev.Pos), ev.To))
				continue
			}
			if want, ok := m.DoneTask(ev.Place.Root); !ok || want != ev.To {
				reasons = append(reasons, fmt.Sprintf("%s: join assertion for %s is not backed by that task's done channel", m.Prog.Pos(ev.Pos), ev.To))
				continue
			}
			st.returnTo(ev.To, ev.Task)
		}
		if len(reasons) > 12 {
			break
		}
	}
	return reasons
}

type segment struct {
	place artifact.Place
	owner string
}

type state struct {
	segs []segment
}

func (s *state) add(p artifact.Place, owner string) {
	s.segs = append(s.segs, segment{place: p, owner: owner})
}

func (s *state) indexOf(task string, p artifact.Place) int {
	for i, sg := range s.segs {
		if sg.owner == task && sg.place.Covers(p) {
			return i
		}
	}
	return -1
}

func (s *state) holds(task string, p artifact.Place) bool {
	return s.indexOf(task, p) >= 0
}

func (s *state) take(from string, p artifact.Place, to string) bool {
	i := s.indexOf(from, p)
	if i < 0 {
		return false
	}
	sg := s.segs[i]
	s.segs = append(s.segs[:i], s.segs[i+1:]...)
	if sg.place.Lo < p.Lo {
		s.add(artifact.Place{Root: sg.place.Root, Lo: sg.place.Lo, Hi: p.Lo}, from)
	}
	if p.Hi < sg.place.Hi {
		s.add(artifact.Place{Root: sg.place.Root, Lo: p.Hi, Hi: sg.place.Hi}, from)
	}
	s.add(p, to)
	return true
}

func (s *state) returnTo(task, parent string) {
	changed := true
	for changed {
		changed = false
		for i := range s.segs {
			if s.segs[i].owner == task {
				s.segs[i].owner = parent
				changed = true
			}
		}
	}
}
