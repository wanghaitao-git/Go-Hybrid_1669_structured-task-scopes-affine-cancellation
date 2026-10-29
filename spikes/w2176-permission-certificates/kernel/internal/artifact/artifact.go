// Package artifact turns an emitted Go artifact into the model the kernel
// checks against: typed roots, aliases, per-task memory operations, and the
// replay order. Nothing here reads a hy-check verdict; every fact is
// recomputed from the Go text.
package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"strconv"
)

type Kind int

const (
	KindScalar Kind = iota
	KindSlice
	KindChan
)

type Place struct {
	Root int
	Lo   int
	Hi   int
}

func (p Place) String() string {
	return fmt.Sprintf("R%d[%d:%d]", p.Root, p.Lo, p.Hi)
}

func (p Place) Covers(o Place) bool {
	return p.Root == o.Root && p.Lo <= o.Lo && o.Hi <= p.Hi
}

func (p Place) Overlaps(o Place) bool {
	return p.Root == o.Root && p.Lo < o.Hi && o.Lo < p.Hi
}

type Root struct {
	ID   int
	Pos  token.Pos
	Len  int
	Kind Kind
}

type EventKind int

const (
	EvAlloc EventKind = iota
	EvRead
	EvWrite
	EvTransfer
	EvJoin
)

func (k EventKind) String() string {
	switch k {
	case EvAlloc:
		return "alloc"
	case EvRead:
		return "read"
	case EvWrite:
		return "write"
	case EvTransfer:
		return "transfer"
	case EvJoin:
		return "join"
	}
	return "?"
}

type Event struct {
	Kind  EventKind
	Task  string
	Pos   token.Pos
	Place Place
	To    string
}

type Prog struct {
	Fset      *token.FileSet
	Info      *types.Info
	Pkg       *types.Package
	File      *ast.File
	Main      *ast.FuncDecl
	Fns       map[string]*ast.FuncDecl
	Roots     []Root
	rootByPos map[token.Pos]int
	Digest    string
	Path      string
}

type Model struct {
	Prog       *Prog
	Events     []Event
	Tasks      []string
	TaskCallee map[string]string
	TaskPos    map[string]token.Pos
	doneRoots  map[int]string
	Limit      string
	Broken     []string
}

// Load parses and type-checks the artifact and records its normalized digest.
func Load(path string) (*Prog, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(normalize(src))
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	info := &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{},
		Defs:  map[*ast.Ident]types.Object{},
		Uses:  map[*ast.Ident]types.Object{},
	}
	var typeErr error
	conf := types.Config{Error: func(e error) {
		if typeErr == nil {
			typeErr = e
		}
	}}
	pkg, err := conf.Check("artifact", fset, []*ast.File{file}, info)
	if typeErr != nil {
		return nil, fmt.Errorf("type check: %w", typeErr)
	}
	if err != nil && typeErr == nil {
		return nil, fmt.Errorf("type check: %w", err)
	}

	p := &Prog{
		Fset:      fset,
		Info:      info,
		Pkg:       pkg,
		File:      file,
		Fns:       map[string]*ast.FuncDecl{},
		rootByPos: map[token.Pos]int{},
		Digest:    hex.EncodeToString(sum[:]),
		Path:      path,
	}
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok {
			if fd.Recv != nil {
				return nil, fmt.Errorf("methods are outside the certified subset")
			}
			p.Fns[fd.Name.Name] = fd
		}
	}
	p.Main = p.Fns["main"]
	if p.Main == nil {
		return nil, fmt.Errorf("artifact has no func main")
	}
	return p, nil
}

func normalize(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '\r' && i+1 < len(b) && b[i+1] == '\n' {
			continue
		}
		out = append(out, b[i])
	}
	return out
}

func (p *Prog) Pos(x token.Pos) string {
	pos := p.Fset.Position(x)
	return fmt.Sprintf("%d:%d", pos.Line, pos.Column)
}

func (p *Prog) KindOf(e ast.Expr) Kind {
	tv, ok := p.Info.Types[e]
	if !ok || tv.Type == nil {
		return KindScalar
	}
	return kindOf(tv.Type)
}

func kindOf(t types.Type) Kind {
	switch u := t.(type) {
	case *types.Slice:
		if kindOf(u.Elem()) != KindScalar {
			return Kind(-1)
		}
		return KindSlice
	case *types.Chan:
		if kindOf(u.Elem()) != KindScalar {
			return Kind(-1)
		}
		return KindChan
	case *types.Basic:
		if u.Info()&(types.IsInteger|types.IsString|types.IsBoolean) != 0 {
			return KindScalar
		}
		return Kind(-1)
	}
	return Kind(-1)
}

// Build computes the replay order: the entry task's operations in source
// order, with each spawned task's operations spliced in at its spawn event.
// This is faithful for the admitted subset because ownership is exclusive:
// the parent cannot touch what it transferred, so the child's interleaving
// is unobservable to every later parent operation.
func (p *Prog) Build() *Model {
	m := &Model{
		Prog:       p,
		Tasks:      []string{"T0"},
		TaskCallee: map[string]string{"T0": "entry"},
		TaskPos:    map[string]token.Pos{"T0": p.Main.Pos()},
		doneRoots:  map[int]string{},
	}
	if why := p.supported(); why != "" {
		m.Limit = why
		return m
	}

	b := &builder{m: m, env: map[types.Object]Place{}}
	b.task = "T0"
	b.fn = p.Main
	b.bindParams(p.Main, nil, nil)
	b.stmts(p.Main.Body.List, 0)
	m.Events = b.events
	m.Broken = b.broken
	return m
}

type builder struct {
	m      *Model
	fn     *ast.FuncDecl
	task   string
	env    map[types.Object]Place
	events []Event
	broken []string
}

func (b *builder) fail(pos token.Pos, format string, args ...any) {
	b.broken = append(b.broken, fmt.Sprintf("%s: %s", b.m.Prog.Pos(pos), fmt.Sprintf(format, args...)))
}

func (b *builder) emit(kind EventKind, pos token.Pos, place Place, to string) {
	b.events = append(b.events, Event{Kind: kind, Task: b.task, Pos: pos, Place: place, To: to})
}

func (b *builder) bindParams(fd *ast.FuncDecl, argPlaces []Place, argKinds []Kind) {
	if fd.Type.Params == nil {
		return
	}
	i := 0
	for _, field := range fd.Type.Params.List {
		if len(field.Names) == 0 {
			continue
		}
		k := kindOf(b.m.Prog.Info.Defs[field.Names[0]].Type())
		for _, n := range field.Names {
			obj := b.m.Prog.Info.Defs[n]
			if k == KindSlice || k == KindChan {
				if i < len(argPlaces) && argKinds[i] == k {
					b.env[obj] = argPlaces[i]
				}
			}
			i++
		}
	}
}

// placeOf resolves an expression that denotes storage. A reference copy
// keeps its parent's backing root and interval; only an allocation site
// creates a new root.
func (b *builder) placeOf(e ast.Expr) (Place, bool) {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return b.placeOf(x.X)
	case *ast.Ident:
		obj := b.m.Prog.Info.Uses[x]
		if obj == nil {
			obj = b.m.Prog.Info.Defs[x]
		}
		pl, ok := b.env[obj]
		return pl, ok
	case *ast.CallExpr:
		if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "make" {
			if r, ok := b.alloc(x); ok {
				return Place{Root: r.ID, Lo: 0, Hi: r.Len}, true
			}
		}
		return Place{}, false
	case *ast.CompositeLit:
		if r, ok := b.alloc(x); ok {
			return Place{Root: r.ID, Lo: 0, Hi: r.Len}, true
		}
		return Place{}, false
	case *ast.SliceExpr:
		base, ok := b.placeOf(x.X)
		if !ok {
			return Place{}, false
		}
		lo, hi := 0, base.Hi-base.Lo
		if x.Low != nil {
			n, ok := constInt(x.Low)
			if !ok {
				b.fail(x.Low.Pos(), "slice bound is not a constant")
				return Place{}, false
			}
			lo = n
		}
		if x.High != nil {
			n, ok := constInt(x.High)
			if !ok {
				b.fail(x.High.Pos(), "slice bound is not a constant")
				return Place{}, false
			}
			hi = n
		}
		if x.Max != nil {
			b.fail(x.Max.Pos(), "three-index slice is outside the certified subset")
			return Place{}, false
		}
		if lo < 0 || hi < lo || hi > base.Hi-base.Lo {
			b.fail(x.Pos(), "slice [%d:%d] is outside the reference length %d", lo, hi, base.Hi-base.Lo)
			return Place{}, false
		}
		return Place{Root: base.Root, Lo: base.Lo + lo, Hi: base.Lo + hi}, true
	}
	return Place{}, false
}

// alloc records an allocation site as a fresh root. Identity comes from the
// syntax position, never from a producer-supplied label.
func (b *builder) alloc(e ast.Expr) (Root, bool) {
	if id, ok := b.m.Prog.rootByPos[e.Pos()]; ok {
		for _, r := range b.m.Prog.Roots {
			if r.ID == id {
				return r, true
			}
		}
	}
	r, err := b.m.Prog.newRoot(e)
	if err != nil {
		b.fail(e.Pos(), "%v", err)
		return Root{}, false
	}
	b.emit(EvAlloc, e.Pos(), Place{Root: r.ID, Lo: 0, Hi: r.Len}, "")
	return r, true
}

func constInt(e ast.Expr) (int, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.INT {
			return 0, false
		}
		n, err := strconv.Atoi(x.Value)
		return n, err == nil
	case *ast.ParenExpr:
		return constInt(x.X)
	}
	return 0, false
}

func (p *Prog) newRoot(e ast.Expr) (Root, error) {
	var length int
	var kind Kind
	switch x := e.(type) {
	case *ast.CallExpr:
		id, ok := x.Fun.(*ast.Ident)
		if !ok || id.Name != "make" || len(x.Args) < 1 {
			return Root{}, fmt.Errorf("allocation is not a statically sized make")
		}
		if kind = p.KindOf(x); kind != KindSlice && kind != KindChan {
			return Root{}, fmt.Errorf("make of an unsupported type")
		}
		if kind == KindChan {
			length = 1
			break
		}
		if len(x.Args) < 2 {
			return Root{}, fmt.Errorf("slice allocation has no length")
		}
		n, ok := constInt(x.Args[1])
		if !ok || n <= 0 {
			return Root{}, fmt.Errorf("make length is not a positive constant")
		}
		length = n
	case *ast.CompositeLit:
		if p.KindOf(x) != KindSlice {
			return Root{}, fmt.Errorf("composite literal is not a slice")
		}
		length = len(x.Elts)
		if length == 0 {
			return Root{}, fmt.Errorf("empty slice literal has no storage")
		}
	default:
		return Root{}, fmt.Errorf("not an allocation")
	}
	r := Root{ID: len(p.Roots) + 1, Pos: e.Pos(), Len: length, Kind: kind}
	p.Roots = append(p.Roots, r)
	p.rootByPos[e.Pos()] = r.ID
	return r, nil
}

// scalar checks a value is scalar-typed, so that passing it across a
// boundary carries no storage.
func (b *builder) scalar(e ast.Expr) bool {
	k := b.m.Prog.KindOf(e)
	if k == KindScalar {
		return true
	}
	return false
}

func (b *builder) stmts(list []ast.Stmt, condDepth int) {
	for _, s := range list {
		b.stmt(s, condDepth)
	}
}

func (b *builder) stmt(s ast.Stmt, condDepth int) {
	switch x := s.(type) {
	case *ast.BlockStmt:
		b.stmts(x.List, condDepth)
	case *ast.AssignStmt:
		b.assign(x, condDepth)
	case *ast.DeclStmt:
		if gd, ok := x.Decl.(*ast.GenDecl); ok {
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					b.fail(spec.Pos(), "unsupported declaration")
					continue
				}
				for i, n := range vs.Names {
					var obj types.Object = b.m.Prog.Info.Defs[n]
					if vs.Values == nil {
						if ts, ok := vs.Type.(*ast.ArrayType); ok {
							b.fail(ts.Pos(), "uninitialised slice declaration is outside the certified subset")
						}
						continue
					}
					if i >= len(vs.Values) {
						continue
					}
					v := vs.Values[i]
					if k := b.m.Prog.KindOf(v); k == KindSlice || k == KindChan {
						if pl, ok := b.placeOf(v); ok {
							b.env[obj] = pl
						}
					}
					b.expr(v, condDepth)
				}
			}
		}
	case *ast.ExprStmt:
		b.expr(x.X, condDepth)
	case *ast.SendStmt:
		if k := b.m.Prog.KindOf(x.Value); k != KindScalar {
			b.fail(x.Pos(), "channel-carried ownership is outside the certified subset")
			return
		}
		if b.m.Prog.KindOf(x.Chan) != KindChan {
			b.fail(x.Pos(), "send on a non-channel")
		}
	case *ast.GoStmt:
		if condDepth > 0 {
			b.fail(x.Pos(), "spawn under a conditional is outside the certified subset")
			return
		}
		b.spawn(x)
	case *ast.IfStmt:
		if x.Init != nil {
			b.fail(x.Pos(), "if with an init statement is outside the certified subset")
			return
		}
		b.expr(x.Cond, condDepth)
		b.stmts(x.Body.List, condDepth+1)
		if x.Else != nil {
			if e, ok := x.Else.(*ast.BlockStmt); ok {
				b.stmts(e.List, condDepth+1)
			} else {
				b.fail(x.Else.Pos(), "else-if chains are outside the certified subset")
			}
		}
	case *ast.ReturnStmt:
		for _, r := range x.Results {
			b.expr(r, condDepth)
		}
	case *ast.IncDecStmt:
		if idx, ok := x.X.(*ast.IndexExpr); ok {
			if pl, ok := b.elementPlace(idx); ok {
				b.emit(EvRead, x.Pos(), pl, "")
				b.emit(EvWrite, x.Pos(), pl, "")
			}
			return
		}
		if b.m.Prog.KindOf(x.X) != KindScalar {
			b.fail(x.Pos(), "increment of a non-scalar")
		}
	default:
		b.fail(s.Pos(), "statement %T is outside the certified subset", s)
	}
}

func (b *builder) assign(a *ast.AssignStmt, condDepth int) {
	if a.Tok != token.ASSIGN && a.Tok != token.DEFINE {
		b.fail(a.Pos(), "compound assignment is outside the certified subset")
		return
	}
	if len(a.Lhs) != len(a.Rhs) {
		b.fail(a.Pos(), "multi-value assignment is outside the certified subset")
		return
	}
	for i, lhs := range a.Lhs {
		rhs := a.Rhs[i]
		switch l := lhs.(type) {
		case *ast.IndexExpr:
			pl, ok := b.elementPlace(l)
			if ok {
				b.emit(EvWrite, a.Pos(), pl, "")
			}
			b.expr(l.Index, condDepth)
			b.expr(rhs, condDepth)
		case *ast.Ident:
			var obj types.Object
			if a.Tok == token.DEFINE {
				obj = b.m.Prog.Info.Defs[l]
			} else {
				obj = b.m.Prog.Info.Uses[l]
			}
			if obj == nil {
				b.fail(l.Pos(), "unresolved assignment target %q", l.Name)
				continue
			}
			if k := b.m.Prog.KindOf(rhs); k == KindSlice || k == KindChan {
				if pl, ok := b.placeOf(rhs); ok {
					b.env[obj] = pl
				} else {
					b.fail(rhs.Pos(), "reference assigned from an expression with no resolved root")
				}
			}
			b.expr(rhs, condDepth)
		default:
			b.fail(lhs.Pos(), "assignment target %T is outside the certified subset", lhs)
		}
	}
}

func (b *builder) elementPlace(idx *ast.IndexExpr) (Place, bool) {
	base, ok := b.placeOf(idx.X)
	if !ok {
		b.fail(idx.Pos(), "index expression has no resolved backing root")
		return Place{}, false
	}
	n, ok := constInt(idx.Index)
	if !ok {
		b.fail(idx.Index.Pos(), "index is not a constant")
		return Place{}, false
	}
	if n < 0 || n >= base.Hi-base.Lo {
		b.fail(idx.Pos(), "index %d is outside the reference length %d", n, base.Hi-base.Lo)
		return Place{}, false
	}
	return Place{Root: base.Root, Lo: base.Lo + n, Hi: base.Lo + n + 1}, true
}

// expr walks a value expression, recording element reads.
func (b *builder) expr(e ast.Expr, condDepth int) {
	switch x := e.(type) {
	case nil:
		return
	case *ast.ParenExpr:
		b.expr(x.X, condDepth)
	case *ast.Ident, *ast.BasicLit:
		return
	case *ast.IndexExpr:
		if pl, ok := b.elementPlace(x); ok {
			b.emit(EvRead, x.Pos(), pl, "")
		}
	case *ast.SliceExpr:
		b.expr(x.X, condDepth)
	case *ast.BinaryExpr:
		b.expr(x.X, condDepth)
		b.expr(x.Y, condDepth)
	case *ast.UnaryExpr:
		if x.Op == token.ARROW {
			b.recv(x, condDepth)
			return
		}
		b.expr(x.X, condDepth)
	case *ast.CallExpr:
		if id, ok := x.Fun.(*ast.Ident); ok {
			switch id.Name {
			case "make", "new":
				if _, ok := b.m.Prog.Info.Uses[id].(*types.Builtin); ok {
					return
				}
			case "len", "cap", "close":
				for _, a := range x.Args {
					b.expr(a, condDepth)
				}
				return
			}
		}
		for _, a := range x.Args {
			b.expr(a, condDepth)
		}
	case *ast.CompositeLit:
		return
	}
}

// recv turns a receive on a spawned task's done channel into a join event.
// The kernel later checks that the channel really is that task's done
// channel, so a certificate cannot join a task that never signals.
func (b *builder) recv(x *ast.UnaryExpr, condDepth int) {
	pl, ok := b.placeOf(x.X)
	if !ok {
		return
	}
	if child, ok := b.m.doneRoots[pl.Root]; ok {
		if condDepth > 0 {
			b.fail(x.Pos(), "join under a conditional is outside the certified subset")
			return
		}
		b.emit(EvJoin, x.Pos(), pl, child)
	}
}

func (b *builder) spawn(g *ast.GoStmt) {
	if b.task != "T0" {
		b.fail(g.Pos(), "spawn inside a spawned task is outside the certified subset")
		return
	}
	call, ok := g.Call.Fun.(*ast.Ident)
	if !ok {
		b.fail(g.Pos(), "spawn of a non-name callee is outside the certified subset")
		return
	}
	fd, ok := b.m.Prog.Fns[call.Name]
	if !ok {
		b.fail(g.Pos(), "spawn callee %q has no derivation in this artifact", call.Name)
		return
	}
	if fd == b.m.Prog.Main {
		b.fail(g.Pos(), "recursive spawn is outside the certified subset")
		return
	}

	var argPlaces []Place
	var argKinds []Kind
	for _, a := range g.Call.Args {
		k := b.m.Prog.KindOf(a)
		argKinds = append(argKinds, k)
		if k == KindSlice || k == KindChan {
			pl, ok := b.placeOf(a)
			if !ok {
				b.fail(a.Pos(), "spawn argument has no resolved backing root")
				argPlaces = append(argPlaces, Place{})
				continue
			}
			argPlaces = append(argPlaces, pl)
		} else {
			argPlaces = append(argPlaces, Place{})
		}
		b.expr(a, 0)
	}

	name := fmt.Sprintf("T%d", len(b.m.TaskPos))
	b.m.TaskPos[name] = g.Pos()
	b.m.TaskCallee[name] = call.Name
	b.m.Tasks = append(b.m.Tasks, name)

	parent, parentFn, parentEnv := b.task, b.fn, b.env
	parentEvents := len(b.events)
	b.task, b.fn, b.env = name, fd, map[types.Object]Place{}
	b.bindParams(fd, argPlaces, argKinds)
	b.stmts(fd.Body.List, 0)
	childEvents := append([]Event(nil), b.events[parentEvents:]...)
	b.events = b.events[:parentEvents]
	b.task, b.fn, b.env = parent, parentFn, parentEnv

	// The done channel is the channel parameter of the child's final send.
	if done, ok := doneRoot(fd, argPlaces, argKinds, b.m.Prog); ok {
		b.m.doneRoots[done] = name
	}

	for i := range g.Call.Args {
		if argKinds[i] != KindSlice && argKinds[i] != KindChan {
			continue
		}
		b.emit(EvTransfer, g.Pos(), argPlaces[i], name)
	}
	b.events = append(b.events, childEvents...)
}

// doneRoot reports the root of the channel a spawned callee signals on as
// its last statement.
func doneRoot(fd *ast.FuncDecl, argPlaces []Place, argKinds []Kind, p *Prog) (int, bool) {
	if fd.Body == nil || len(fd.Body.List) == 0 {
		return 0, false
	}
	send, ok := fd.Body.List[len(fd.Body.List)-1].(*ast.SendStmt)
	if !ok {
		return 0, false
	}
	id, ok := send.Chan.(*ast.Ident)
	if !ok {
		return 0, false
	}
	obj := p.Info.Uses[id]
	if obj == nil {
		return 0, false
	}
	i := 0
	for _, field := range fd.Type.Params.List {
		for _, n := range field.Names {
			if p.Info.Defs[n] == obj {
				if i < len(argKinds) && argKinds[i] == KindChan {
					return argPlaces[i].Root, true
				}
				return 0, false
			}
			i++
		}
	}
	return 0, false
}

// supported reports the first construct outside the admitted subset. An
// unsupported artifact yields no certificate; it must never read as safe.
func (p *Prog) supported() string {
	if len(p.File.Imports) > 0 {
		return "imports are outside the certified subset"
	}
	for _, d := range p.File.Decls {
		switch x := d.(type) {
		case *ast.FuncDecl:
			if x.Recv != nil {
				return "methods are outside the certified subset"
			}
		case *ast.GenDecl:
			if x.Tok != token.CONST {
				return "package-level var/type declarations are outside the certified subset"
			}
		default:
			return fmt.Sprintf("declaration %T is outside the certified subset", d)
		}
	}

	var why string
	ast.Inspect(p.File, func(n ast.Node) bool {
		if why != "" || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt,
			*ast.SelectStmt, *ast.LabeledStmt, *ast.BranchStmt, *ast.DeferStmt,
			*ast.FuncLit, *ast.MapType, *ast.StructType, *ast.InterfaceType,
			*ast.StarExpr, *ast.TypeAssertExpr, *ast.Ellipsis, *ast.SelectorExpr:
			why = fmt.Sprintf("%T is outside the certified subset", x)
		case *ast.GoStmt:
			if _, ok := x.Call.Fun.(*ast.Ident); !ok {
				why = "spawn of a non-name callee is outside the certified subset"
			}
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok {
				switch id.Name {
				case "make", "new", "len", "cap", "close", "append", "copy", "delete", "println", "print":
					if _, isBuiltin := p.Info.Uses[id].(*types.Builtin); isBuiltin {
						switch id.Name {
						case "new", "append", "copy", "delete", "println", "print":
							why = fmt.Sprintf("builtin %q is outside the certified subset", id.Name)
						}
					}
				}
			}
		}
		return true
	})
	if why != "" {
		return why
	}

	for name, fd := range p.Fns {
		for _, field := range fd.Type.Params.List {
			if len(field.Names) == 0 {
				return fmt.Sprintf("%s: unnamed parameters are outside the certified subset", name)
			}
			if k := kindOf(p.Info.TypeOf(field.Type)); k < 0 {
				return fmt.Sprintf("%s: parameter type %s is outside the certified subset", name, p.Info.TypeOf(field.Type))
			}
		}
		if fd.Type.Results != nil {
			for _, field := range fd.Type.Results.List {
				if k := kindOf(p.Info.TypeOf(field.Type)); k < 0 {
					return fmt.Sprintf("%s: result type %s is outside the certified subset", name, p.Info.TypeOf(field.Type))
				}
			}
		}
	}
	return ""
}

// DoneTask reports the spawned task that signals on a channel root, which is
// what makes a join assertion checkable rather than trusted.
func (m *Model) DoneTask(root int) (string, bool) {
	t, ok := m.doneRoots[root]
	return t, ok
}
