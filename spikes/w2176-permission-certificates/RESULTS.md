# RESULTS — W-2176 permission certificates for actual Go (pre-registration)

**Status:** PRE-REGISTERED — this file was committed **before** the kernel
existed and before any case in the battery was executed. Raw results are
appended under "Raw results" only after a run, never edited in place.

**Issue:** [#2176](https://github.com/limitlessprojects/Go-Hybrid/issues/2176)
— make `hy-check` an untrusted proof producer for an opt-in certified
subset: the frontend emits Go plus a candidate permission derivation, and
an independent kernel checks that derivation against the **actual typed Go
CFG**.

**Inspected main:** `1f0ff978f4deff78c77bca96db0e3e46f32de71b`.

---

## 1. What is being tested (the question, not the implementation)

The research question is **not** "can we write a checker". It is:

> Can explicit proof checking remove *inference and search* from the
> trusted safety core without the kernel becoming another full checker?

So the scoreboard is not "does the prototype reject the bad programs". It
is the pair:

1. **Trust reduction:** does the accept/reject decision for the certified
   artifact depend on any `hy-check` conclusion? (Target: no. The kernel
   must recompute allocation identity, aliasing and every memory operation
   from the Go text itself, and treat the certificate only as a *derivation
   to be replayed*.)
2. **Cost:** how many non-generated semantic lines does the kernel need,
   compared with the checker it is meant to stop trusting?

A prototype that only "rechecks what hy-check already decided" fails
regardless of how many falsifiers it rejects. A prototype that is cheap
only because it certifies three programs also fails — shrinking the
language is not a trust reduction.

## 2. Admitted subset (v0), fixed before implementation

Certified artifacts are ordinary **Go** source, one package, one file
`artifact.go`, restricted to:

| Dimension | Admitted in v0 |
|---|---|
| Types | `int`, `string`, `bool`; `[]int`, `[]string`; `chan` of those |
| Allocation | `make([]T, n)` / `make(chan T, n)` with statically known `n`, composite slice literals |
| Aliasing | `y := x`, `y = x[:]`, `y := x[a:b]` with statically known bounds |
| Control flow | sequential statements, `if`/`else`; **no loops** (see below) |
| Concurrency | `go f(args)` spawn of a top-level `func`; unbuffered/known-capacity channel send and receive; `close(ch)`; single-shot done-channel join |
| Calls | static calls to top-level `func`s in the same artifact, each carrying its own checked derivation |
| Excluded → **no certificate** | loops, closures, `defer`/`panic`/`recover`, maps, structs, interfaces, pointers, methods, `unsafe`, reflection, globals, variadics, `select`, buffered channels with unbounded producers, borrowed mutable entry inputs |

**Why no loops is a design decision, not a convenience.** Excluding loops
makes the CFG over the admitted subset a **DAG**. On a DAG, replaying an
explicit derivation is a single topological pass: no fixpoint, no widening,
no invariant inference, no search. This is the strongest available answer
to "does the kernel become another full checker" — it is the property that
must hold, and it is what makes the 2,000-LOC budget plausible at all. A
later milestone that adds loops would have to give up that property and is
explicitly out of scope here.

**Intervals.** A reference denotes the byte/element interval `[0, len)` of
its backing root; element ops are `[i, i+1)`. Reference copies and
re-slices keep the **backing-root identity** and narrow the interval. Only
an allocation rule creates freshness. (`x[:1]` and `x` are the *same* root
with different intervals — the entire point of the illustrative negative
case.)

## 3. Trust ledger (fixed before implementation)

**Trusted even after a certificate is accepted:**

| Component | Why it stays trusted | Reducible later? |
|---|---|---|
| Go parser (`go/parser`) | the kernel reads the artifact through it | shared with `cmd/compile`; not ours to shrink |
| Go type resolution (`go/types`) | shapes, intervals, callee signatures | ditto |
| Kernel implementation (`hycert`, this spike) | it *is* the checking core | target: ≤2,000 semantic LOC, no search, no SMT |
| Go compiler + runtime | the artifact is compiled and scheduled by them | out of scope (GUARANTEES rows 17–20) |

**No longer trusted for the certified artifact's race-freedom:**

| Component | Today | With a certificate |
|---|---|---|
| `hy-check` sendability classification (row 1–3: spawn args, sends, deep composites) | trusted source of "sendable"/"moved"/"frozen" | **not trusted**: its output is a *hint*; the kernel recomputes roots and aliases and rejects forged labels |
| `hy-check` move/freeze bookkeeping (`freeze.rs`, `loans.rs`) | trusted | **not trusted** for the certified artifact: ownership is a permission in the derivation, checked against real spawn/send edges |
| `hy-emit` move erasure (`stmt.rs:39–69`) | the reason no evidence exists in the artifact | unchanged — the certificate, not the emitted text, carries the evidence |

`go.mod` of the kernel carries **no third-party dependency** and no
SMT solver. Any dependency added later counts against the trust reduction
and must be argued in the ledger above.

## 4. Pre-registered predictions (committed before the run)

Every row is a prediction, not a result. "REJECT" and "NO-CERT" are the
kernel's two distinct failure classes: **REJECT** = a derivation was
supplied and the kernel proved it wrong (the interesting class);
**NO-CERT** = the artifact is outside the subset, or the derivation or its
binding is absent/ill-formed.

| # | Case | Supplied certificate | Pre-registered outcome |
|---|---|---|---|
| P1 | Supported spawn with real reads/writes, storage uniquely transferred to the child, joined once | complete, honest | **ACCEPT** |
| P2 | Disjoint split: `go w(x[:2])`, `go w(x[2:4])` on one `make([]int,4)` | complete, honest | **ACCEPT** |
| P3 | Illustrative case from the issue: `x := make([]int,2); alias := x[:1]; go write(x); alias[0] = 1` | forged: claims `alias` stays writable by the parent after the spawn | **REJECT** (surviving-alias write after transfer) |
| P4 | Same artifact as P3 | *no* certificate at all | **NO-CERT** (this is the today's-emitted-Go baseline) |
| P5 | Overlapping concurrent writes: `go w(x[:3])`, `go w(x[2:4])` | complete, honest | **REJECT** (overlapping exclusive permissions) |
| P6 | Forged freshness: `y := x; go w(y)` with a certificate that calls `y` a fresh root | forged labels | **REJECT** (kernel recomputes backing root; label contradicts syntax) |
| P7 | Omitted obligation: a real element write in the artifact with no step covering it | incomplete-by-omission | **REJECT** (uncovered memory operation) |
| P8 | Fabricated step: certificate cites a line/column with no memory operation | forged | **REJECT** |
| P9 | Type-correct unsafe mutation: `alias[0] = 1` after the root was transferred, where `alias` is an element re-slice | forged: asserts exclusive parent permission | **REJECT** |
| P10 | Unsupported construct in the artifact (a `for` loop) | complete, honest | **NO-CERT** |
| P11 | Changed artifact: certificate digest taken from a different file | any | **NO-CERT** (binding) |
| P12 | Incomplete derivation: complete steps, missing `join` assertion | honest but incomplete | **NO-CERT** |
| P13 | Race-free but functionally wrong artifact (child computes the wrong value; no data race) | complete, honest | **ACCEPT** — safety pass, and the artifact must still be **caught by the separate behaviour gate**, which this kernel does not implement |
| P14 | Program outside the subset that is genuinely racy, supplied with a certificate | any | **NO-CERT** (not ACCEPT — an unsupported construct must never read as safe) |
| P15 | Same admitted program as P1, but with the artifact's `move`-equivalent spawn arg swapped to a surviving alias and the certificate *unchanged* | stale | **REJECT** or **NO-CERT**, never ACCEPT |

**Predictions about the kernel itself:**

| # | Prediction |
|---|---|
| K1 | Kernel semantic core (parser of the certificate format + artifact model + replay rules) is **≤2,000** non-blank, non-comment lines, excluding tests and `testdata/`. |
| K2 | The replay is **linear in the number of steps and nodes**: one topological pass over a DAG, no fixpoint, no backtracking, no solver call. Verification is O(nodes + steps). |
| K3 | No rule consults a `hy-check` verdict or any label supplied by the producer without recomputing it from the artifact. A certificate that is internally consistent but contradicts the Go text is rejected on the text. |
| K4 | The kernel's own source remains a trust assumption: accepting a certificate says nothing about kernel bugs. This spike demonstrates *feasibility and cost*, not soundness of the kernel. |

## 5. What would falsify the thesis

Taken from the issue, made concrete for this spike. Any of these firing is
a publishable negative outcome, which is the point of the track:

- F1: A meaningful positive case cannot be certified → the subset that
  survives is too small to matter.
- F2: An unsafe variant passes → the kernel is not a safety argument.
- F3: Permissions still depend on a trusted `hy-check` label → no trust
  boundary was moved.
- F4: The kernel re-implements the existing search (fixpoint, invariant
  inference) → it became another full checker.
- F5: The kernel exceeds the LOC budget by a wide margin → cost honesty
  fails, and the writeup must say so.

## 6. Raw results

Executed 2026-10-29 on Windows 11 / Go 1.27.3 (`go test ./...` in `kernel/`,
module `hycert`, no external dependencies).

### 6.1 Falsifier battery — prediction vs. observed

| # | Case (fixture) | Predicted | Observed | Reason line the kernel printed |
|---|---|---|---|---|
| P1 | `p01-accept` | ACCEPT | **ACCEPT** | `checked 9 events against 7 derivation steps` |
| P2 | `p02-disjoint-accept` | ACCEPT | **ACCEPT** | `checked 14 events against 11 derivation steps` |
| P3 | `p03-surviving-alias` | REJECT | **REJECT** | `13:2: write R1[0:1] by T0 without permission on the overlapping storage` |
| P4 | `p04-no-cert` | NO-CERT | **NO-CERT** | `no certificate supplied` |
| P5 | `p05-overlap` | REJECT | **REJECT** | `13:2: transfer R1[2:4] from T0 to T2 without holding it` |
| P6 | `p06-forged-fresh` | REJECT | **REJECT** | `root inventory contradicts the artifact: certificate declares 3, artifact has 2 allocation sites` |
| P7 | `p07-omitted-op` | REJECT | **REJECT** | `uncovered memory operation (1 left): T0 10:2 write R1[0:1]` |
| P8 | `p08-fabricated-step` | REJECT | **REJECT** | `10:3: write step names a place or task with no such operation in the artifact` |
| P9 | `p09-live-element-write` | REJECT | **REJECT** | `12:2: write R1[0:1] by T0 without permission on the overlapping storage` |
| P10 | `p10-loop-no-cert` | NO-CERT | **NO-CERT** | `artifact is outside the certified subset: *ast.ForStmt …` |
| P11 | `p11-changed-artifact` | NO-CERT | **NO-CERT** | `artifact digest mismatch: certificate binds 911599b0ba89…, artifact is 9cf13955f171…` † |
| P12 | `p12-missing-join` | NO-CERT | **NO-CERT** | `derivation is incomplete: 1 join assertion(s) missing` |
| P13 | `p13-wrong-but-safe` | ACCEPT | **ACCEPT** | `checked 8 events against 6 derivation steps` |
| P14 | `p14-unsupported-racy` | NO-CERT | **NO-CERT** | `artifact is outside the certified subset: package-level var/type declarations …` |
| P15 | `p15-omitted-new-op` | REJECT | **REJECT** | `uncovered memory operation (1 left): T0 14:19 write R1[0:1]` |

15/15 match the pre-registered outcome, including the two deliberate
"must still pass" rows (P2, P13).

† The first run of P11 printed `a9645377e01a…`, a digest taken before the
fixture's final line was settled. The committed artifact hashes
`9cf13955f171…` and reproduces identically on Windows and Linux (§6.4).
The prediction (NO-CERT, binding failure) never depended on the value; the
row now records what a re-run of the committed tree prints.

Two notes on what these rows do **not** show:

- P6's rejection is the inventory check firing, not a replay check: the
  producer declared three allocations where the artifact has two. A sharper
  forgery — keeping the count right and mislabelling an alias — is not
  expressible, because the certificate carries no alias claims at all;
  aliasing is recomputed from the text, so the only place to lie is a
  *step's* place, and `TestCertificateIsCheckedAgainstText` covers that
  (a transfer naming root `R9` in a two-root artifact is rejected).
- P4 is the honest baseline: the artifact in `p03` is exactly what the emit
  path produces today, and it earns no certificate. That is the gap the
  proposal is about, not a defect in the kernel.

### 6.2 Kernel prediction results

| # | Prediction | Observed |
|---|---|---|
| K1 | ≤2,000 semantic LOC | **1,398** non-blank non-comment lines across `main.go` (65), `internal/cert/cert.go` (227), `internal/artifact/artifact.go` (743), `internal/kernel/kernel.go` (321), `internal/kernel/dump.go` (42). Tests (176 lines across the two `_test.go` files) and `testdata/` excluded. |
| K2 | Linear replay, no search | Holds structurally and is exercised by `TestScaling`: events/steps grow 1:1 with operations (50→50, 100→100, 200→200, 400→400, 800→800 steps) and every size verifies in well under a millisecond (measurement resolution on this box is ~0.5 ms, so the timings are a datapoint, not a benchmark). The replay is one forward pass over the event list plus a map lookup per step; no fixpoint, no backtracking, no solver. |
| K3 | No rule consults a producer label | Holds. The kernel's only inputs are the Go source and the certificate; roots, intervals, aliasing, task creation and every memory operation are recomputed. A certificate contributes *decisions* (which task holds which place when) and a *binding* (digest, build claim), never a verdict. |
| K4 | Kernel source remains trusted | Holds and cannot be discharged by a prototype. §7 of the README lists what a bug in this kernel would let through. |

### 6.3 Thesis falsifiers F1–F5

| # | Falsifier | Outcome |
|---|---|---|
| F1 | Positive cases cannot be certified | **Did not fire** for the admitted subset: two independent positive shapes (unique transfer; disjoint split across two tasks) are certified. It *would* fire immediately for anything with a loop, and the subset is small on purpose — see the limits list. |
| F2 | An unsafe variant passes | **Did not fire**: 9 of 9 unsafe/forged variants were rejected or refused a certificate. |
| F3 | Permissions still depend on a trusted `hy-check` label | **Did not fire**: the kernel has no hy-check input at all; the certificate format cannot express "sendable" or "fresh". |
| F4 | The kernel re-implements the existing search | **Did not fire**, but only because loops are excluded (DAG). The moment loops are admitted, a fixpoint comes back; this is the real boundary of the result and is stated in the README. |
| F5 | The kernel blows the LOC budget | **Did not fire**: 1,398 vs the 2,000 budget, with Go's parser and type checker doing the front-end work (those are exactly the dependencies the issue says to list separately). |

### 6.4 Cross-platform check — Ubuntu 26.04, exact committed blobs

Re-ran the whole suite on a Linux guest to make sure nothing in §6.1 is a
Windows artifact:

| | |
|---|---|
| Guest | Ubuntu 26.04.1 LTS (GNOME desktop, VirtualBox 7.2.22, 4 vCPU / 8 GB), Go 1.27.3 linux/amd64 from the official tarball |
| Content transferred | the commit's blobs, extracted with `git cat-file blob`; `git archive` was **not** used because on a host with `core.autocrlf=true` it applies the smudge filter and ships CRLF — the first sync silently produced CRLF and `gofmt -l` flagged all 39 files |
| Byte check | sha256 of all 39 files identical host vs. guest |
| Build / vet | OK |
| `go test ./...` | PASS — battery 15/15, `TestNoCertificateForUnsupported`, `TestCertificateIsCheckedAgainstText`, `TestScaling` |
| `gofmt -l .` | only `testdata/p15-omitted-new-op/artifact.go`, the documented exception |
| K1 | 1,398 semantic LOC (65 + 227 + 743 + 321 + 42), same as Windows |
| K2 | events/steps 1:1 at n=50…800; wall 37.5 µs / 166 µs / 138 µs / 300 µs / 471 µs |
| Offline | `GOPROXY=off` build and test both pass with an empty `GOCACHE`; zero modules in the module cache — the "no dependency" claim is enforced by the build, not just asserted |
| CLI matrix | same 15 verdicts and the same exit codes (0/1/2) as §6.1 |

Digests are stable across the two platforms (`p01` binds `911599b0…`,
`p13` `06ace95c…`), which is what makes rule R1 portable: the binding is
over CRLF-normalized text, not over raw file bytes. The only difference
found was the stale P11 value marked † above.

## 7. Run log

```
2026-10-29  git clone (proxy 127.0.0.1:7890; direct github access is reset from this host)
2026-10-29  commit 1: RESULTS.md pre-registration (before any kernel code)
2026-10-29  implemented kernel/: cert parser, artifact model, replay, CLI, dump
2026-10-29  go build ./...            OK
2026-10-29  go vet ./...              OK
2026-10-29  gofmt -l .                 clean except testdata/p15 (unformatted on purpose: the
                                      semicolon-joined second write is what P15 exercises)
2026-10-29  go test ./...             ok hycert/internal/kernel  (battery + scaling)
2026-10-29  hycert -src … -cert …     P1..P15 as tabulated in §6.1
2026-10-29  Ubuntu 26.04 guest: go1.27.3 linux/amd64 from go.dev tarball (proxy)
2026-10-29  Ubuntu 26.04 guest: exact-blob sync via git cat-file; sha256 equal for all 39 files
2026-10-29  Ubuntu 26.04 guest: build/vet/test PASS; gofmt -l only testdata/p15;
                                      K1 1,398; battery 15/15; §6.4
2026-10-29  P11 digest corrected to the committed artifact's value (†)
```

Reproduce:

```bash
cd spikes/w2176-permission-certificates/kernel
go test ./... -v
go run . -src testdata/p03-surviving-alias/artifact.go -cert testdata/p03-surviving-alias/cert.txt
go run . -src testdata/p13-wrong-but-safe/artifact.go -dump   # producer helper
```

