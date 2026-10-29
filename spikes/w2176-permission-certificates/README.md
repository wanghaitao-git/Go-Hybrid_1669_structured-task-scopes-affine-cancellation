# W-2176 — `hy-check` as an untrusted proof producer

**Wildcard spike for issue [#2176](https://github.com/limitlessprojects/Go-Hybrid/issues/2176).**
Status: M1 artifact — written hypothesis, exact case/mutation inventory, trust
ledger, and a measured prototype. Pre-registration and raw results:
[RESULTS.md](RESULTS.md). Inspected main: `1f0ff97`.

---

## 1. The hypothesis

> For an opt-in certified subset, the emitted Go artifact can carry its own
> safety evidence. Neither `hy-check`'s classification nor `hy-emit`'s move
> bookkeeping has to be trusted for the artifact's race-freedom claim: the
> frontend may only *propose* a permission derivation, and an independent
> kernel replays that derivation against the **actual typed Go**, recomputing
> allocation identity, aliasing, and every memory operation from the text.

The research question is not "can a second checker be written". It is:

> Does explicit proof checking remove **inference and search** from the
> trusted core, without the kernel growing into another full checker?

Cost honesty up front: for the subset implemented here, the answer is *yes*,
under one structural condition — **no loops**, which keeps the CFG a DAG and
makes replay a single forward pass. Drop that condition and a fixpoint comes
back, which is where the thesis starts to cost real money (§7).

## 2. Which assumption it breaks

Today the trusted core for a boundary safety claim is the checker:

- `compiler/crates/hy-emit/src/stmt.rs:39` — "`move` markers drop here:
  ownership transfer is a CHECKER concept; Go sends the value either way."
  The artifact contains no evidence at all.
- `hy-check/src/sendability.rs` (3,227 lines) decides the six sendable
  classes; `freeze.rs` (1,405) and `loans.rs` (8,634) track moves and loans.
  `GUARANTEES.md` rows 1–3 are claims *about that code being right*.

This spike moves the claim to the artifact: `hy-check` becomes an untrusted
producer whose output is a candidate derivation, and the artifact's
race-freedom is proved (or not) by a kernel that never sees a `hy-check`
verdict — it cannot, because the certificate format has no field for
"sendable" or "fresh".

## 3. Trust ledger

**Still trusted after a certificate is accepted**

| Component | Why | Shrinkable? |
|---|---|---|
| `go/parser`, `go/types` | the kernel reads the artifact through them | no — shared with `cmd/compile`; listed as a named assumption, not hidden |
| the kernel (`hycert`, 1,398 semantic LOC) | it *is* the checking core | target of the budget; verified only by tests, not proved |
| Go compiler + runtime | they compile and schedule the artifact | out of scope (GUARANTEES rows 17–20) |

**No longer trusted for the certified artifact**

| Component | Before | After |
|---|---|---|
| sendable classification (row 1–3) | trusted oracle | a hint; recomputed roots contradict forged claims |
| move / freeze / loan bookkeeping | trusted | a permission in the derivation, checked against real spawn and send edges |
| `hy-emit` move erasure | silent gap | irrelevant: evidence lives in the certificate |
| **scope of trust** | 39,251 lines of `hy-check` source | 1,398 lines + stdlib frontend, no SMT solver, no third-party dependency (`go.mod` has none) |

The kernel adds **no solver, no dependency, and no global invariant search**.
Its only inputs are the Go text and the certificate.

## 4. Admitted cases and the mutation inventory

The inventory below is the contract. It was fixed in RESULTS.md §2 before
the kernel existed.

**Admitted (may receive a certificate)** — one package, one file:
scalars; slices of scalars with explicit backing roots; statically sized
`make`; reference copies and constant-bound re-slices; static calls to
top-level `func`s in the artifact; branches; spawn from the entry task;
scalar channel traffic; single-shot done-channel join.

**Everything else → NO-CERT**, never ACCEPT: loops, closures,
`defer`/`panic`/`recover`, maps, structs, interfaces, pointers, methods,
imports, package-level vars/types, variadics, `select`, `unsafe`,
reflection, recursion, spawns from spawned tasks, channel-carried ownership,
and any allocation/transfer/join under a conditional.

**Mutations the kernel must reject** (each has a fixture, §6):

| # | Mutation | Rejected by |
|---|---|---|
| M1 | surviving-alias write after transfer (the issue's illustrative case) | R5/R6 — the parent no longer holds the place |
| M2 | overlapping concurrent writes (`x[:3]` and `x[2:4]` to two tasks) | R6 — the second transfer has no covering segment |
| M3 | forged freshness / sendable labels | R2 — the root inventory is recomputed from allocation sites |
| M4 | omitted operation (a real write with no step) | R3 — coverage is checked in both directions |
| M5 | fabricated step (a position with no operation) | R3 |
| M6 | unsafe type-correct mutation through a live element re-slice | R5 |
| M7 | stale binding (certificate from a different or edited artifact) | R1 |
| M8 | unsupported construct in the artifact | admission check → NO-CERT |
| M9 | incomplete derivation (missing join assertion) | R3 → NO-CERT |

## 5. The certificate and the kernel rules

A certificate is a line-oriented text file: a binding header, the producer's
inventory, and one step per decision.

```
hycert v0
artifact sha256 <hex>                              # R1
build goos=linux,goarch=amd64,goversion=go1.26.9,tags=-
kernel hycert-v0
root R1 9:7 len 2                                  # R2
root R2 11:10 len 1
task T0 8:1 entry                                  # R2
task T1 12:2 spawn:write
step 10:2 write R1[0:1] T0                         # R3, R5
step 12:2 transfer R1[0:2] T0 T1                   # R6
step 12:2 transfer R2[0:1] T0 T1
step 4:2  write R1[0:1] T1
step 13:2 join T1                                  # R7
step 14:2 write R1[1:2] T0
step 14:9 read R1[0:1] T0
```

| Rule | Obligation |
|---|---|
| **R1 binding** | the certificate's digest must equal the artifact's text (CRLF-normalized); a changed artifact earns no certificate |
| **R2 inventory** | the declared roots must equal the kernel's canonical allocation sites (id, position, length), and the declared tasks its spawn sites (id, position, callee). A producer that miscounts storage or calls an alias an allocation is contradicted, not accommodated |
| **R3 coverage** | every memory operation recomputed from the text must have exactly one step, and every step must name an operation that exists. Missing → REJECT; extra → REJECT; missing *join* → NO-CERT |
| **R4 root identity** | reference copies and re-slices keep the backing root and narrow the interval; only an allocation site creates freshness. The certificate cannot assert freshness because it cannot express it |
| **R5 permission** | a read or write of `[lo,hi)` requires the executing task to hold a segment covering that interval |
| **R6 transfer** | a transfer must be made by the holder of a covering segment and splits it, so ownership stays a partition of each root — two live tasks can never hold overlapping storage |
| **R7 join** | a join assertion is accepted only where the artifact receives on that task's done channel (the channel its callee sends on last). A join returns the child's segments to the parent, so post-join use is legal only after a checked join |
| **R8 no search** | the admitted CFG is a DAG; replay is one forward pass plus a map lookup per step |

## 6. Falsification: what was actually run

`kernel/internal/kernel/battery_test.go` runs the 15 pre-registered cases;
[RESULTS.md](RESULTS.md) §6 tabulates prediction vs. observation. Summary:

- **15/15 verdicts matched the pre-registration**, including the two rows
  that must still pass (disjoint split; race-free-but-wrong output).
- The issue's illustrative case
  (`x := make([]int,2); alias := x[:1]; go write(x); alias[0] = 1`) is
  `p03-surviving-alias`, plus the done channel v0's join rule requires:
  **REJECT**, with the reason naming the place and the task — not the
  unsupported-construct escape hatch.
- The same artifact with no certificate is **NO-CERT** (`p04`): that is
  today's emitted Go, and this is the gap the proposal names.
- **K1 (budget)**: 1,398 semantic LOC vs. 2,000.
- **K2 (no search)**: steps grow 1:1 with operations up to 800 ops, each
  verified in well under a millisecond.
- **K3 (no producer labels)**: the kernel has no `hy-check` input.

## 7. Where this is weak — read this before believing any of it

1. **The no-loops condition is doing most of the work.** The "no search"
   result is a consequence of a DAG, not of clever engineering. Admit loops
   and a fixpoint (loop-invariant permission states) reappears — the exact
   thing the thesis says must not creep back. M2 should measure that
   honestly rather than assume it away.
2. **The subset is small enough to be a toy** if it stops here. Slices of
   scalars, static calls, one level of spawning. "Shrinking the language is
   not a trust reduction" applies to this spike in full force.
3. **Reads are exclusive in v0.** Two tasks that both only read the same
   storage are rejected. That is conservative (sound, incomplete) and hides
   the shared-read design question.
4. **Channel-carried ownership is specified but not implemented.** Sending a
   reference on a channel yields NO-CERT rather than a bogus ACCEPT.
5. **The binding is shallow.** The prototype binds the single artifact file's
   text. Real binding needs every input the compiler saw (all files, build
   tags, GOOS/GOARCH, toolchain version). The certificate carries a `build`
   claim; a source-level kernel can check its shape but not its truth.
6. **The kernel is not verified.** A bug in 1,398 lines can accept an unsafe
   program. The claim is that the trust boundary moved and shrank — not that
   the result is proved.
7. **Safety is not behaviour.** `p13` is accepted while computing a wrong
   value on purpose. The behaviour gate is a separate obligation and is not
   implemented here.
8. **The producer is not free.** Something must emit the derivation; here a
   `-dump` helper does, and it is untrusted by construction. If that helper
   has to reason about ownership, the cost may move rather than disappear —
   the honest open question is whether deriving the certificate is cheaper
   than checking it.
9. **Join protocol is picky**: the callee's last statement must send on the
   done channel. Real programs use `WaitGroup`s, `errgroup`, `context` — all
   outside the subset.

## 8. Relation to the neighbouring proposals

| Proposal | Target of distrust | Property proved | Relation |
|---|---|---|---|
| [W-013 / #345](https://github.com/limitlessprojects/Go-Hybrid/issues/345) | `hy-emit` | the actual Go preserves the checked-effect IR | **complementary**: W-013 keeps the checker trusted and validates translation; this keeps the checker untrusted and validates the target property directly. The two kernels should share the Go-side front end, and this one could serve as W-013's Go-side oracle |
| [W-004 / #174](https://github.com/limitlessprojects/Go-Hybrid/issues/174) | `hy-check` inference | use-after-move, via phantom witnesses and `cmd/compile` | **different mechanism**: witnesses put evidence *into the artifact*, this puts it *beside* the artifact. Witnesses inherit Go type-checking; this kernel rejects unsupported captures instead |
| [W-023 / #565](https://github.com/limitlessprojects/Go-Hybrid/issues/565) | the checker's rules | "accepted ⇒ buildable", via a toolchain oracle | **different evidence class**: finitely many successful runs are not a derivation; a certificate is |
| `hy-check` itself | — | sendability of `.hy` at two check-sites | the kernel checks a *different artifact* (Go, not `.hy`) with *interval precision* `hy-check`'s `may_share` abstraction does not have |

If maintainers group this with W-013 as one family, that is a reasonable
call: the shared piece is "the Go artifact is the object being trusted".
The distinguishing claim here is the trust boundary on the *checker*, not
on the emitter.

## 9. What M2 would measure

1. Add loops and report the true cost of the returning fixpoint (LOC delta,
   invariant format, whether the kernel becomes "another checker" — with a
   pre-registered kill line).
2. Add shared-read permissions and measure how much of the subset becomes
   certifiable without loosening R5/R6.
3. Implement channel-carried ownership (the send side of `p05`-style split
   ownership).
4. Price the producer: how many lines does an honest derivation generator
   need, and does `hy-emit` already have the information?

## 10. Reproduce

```bash
cd spikes/w2176-permission-certificates/kernel
go test ./... -v                       # battery + scaling
go run . -src testdata/p03-surviving-alias/artifact.go -cert testdata/p03-surviving-alias/cert.txt
go run . -src testdata/p13-wrong-but-safe/artifact.go -dump   # producer helper, untrusted
```

Exit codes: `0` ACCEPT, `1` REJECT, `2` NO-CERT. The CLI prints the rule that
fired, never a bare verdict.
