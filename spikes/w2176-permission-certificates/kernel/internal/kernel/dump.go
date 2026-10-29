package kernel

import (
	"fmt"
	"strings"

	"hycert/internal/artifact"
)

// Dump prints the derivation the kernel expects for this artifact. It is a
// producer helper: the kernel never consults it, and a certificate built this
// way is still checked line by line against the Go text.
func Dump(m *artifact.Model) string {
	var b strings.Builder
	fmt.Fprintf(&b, "hycert v0\n")
	fmt.Fprintf(&b, "artifact sha256 %s\n", m.Prog.Digest)
	fmt.Fprintf(&b, "build goos=linux,goarch=amd64,goversion=go1.26.9,tags=-\n")
	fmt.Fprintf(&b, "kernel %s\n", KernelVersion)
	if m.Limit != "" {
		fmt.Fprintf(&b, "# artifact is outside the certified subset: %s\n", m.Limit)
		return b.String()
	}
	for _, why := range m.Broken {
		fmt.Fprintf(&b, "# illegal operation: %s\n", why)
	}
	for _, r := range m.Prog.Roots {
		fmt.Fprintf(&b, "root R%d %s len %d\n", r.ID, m.Prog.Pos(r.Pos), r.Len)
	}
	for _, t := range m.Tasks {
		kind := "entry"
		if t != "T0" {
			kind = "spawn:" + m.TaskCallee[t]
		}
		fmt.Fprintf(&b, "task %s %s %s\n", t, m.Prog.Pos(m.TaskPos[t]), kind)
	}
	for _, ev := range m.Events {
		pos := m.Prog.Pos(ev.Pos)
		switch ev.Kind {
		case artifact.EvRead, artifact.EvWrite:
			fmt.Fprintf(&b, "step %s %s %s %s\n", pos, ev.Kind, ev.Place, ev.Task)
		case artifact.EvTransfer:
			fmt.Fprintf(&b, "step %s transfer %s %s %s\n", pos, ev.Place, ev.Task, ev.To)
		case artifact.EvJoin:
			fmt.Fprintf(&b, "step %s join %s\n", pos, ev.To)
		}
	}
	return b.String()
}
