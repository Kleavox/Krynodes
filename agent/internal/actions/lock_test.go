package actions

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type lockGraph struct {
	calls   map[string][]string
	lockers map[string]bool
	saves   map[string]bool
	called  map[string]bool
}

func readLockGraph(t *testing.T) lockGraph {
	t.Helper()
	graph := lockGraph{calls: map[string][]string{}, lockers: map[string]bool{}, saves: map[string]bool{}, called: map[string]bool{}}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	set := token.NewFileSet()
	var decls []*ast.FuncDecl
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(set, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			if function, ok := decl.(*ast.FuncDecl); ok && function.Body != nil {
				decls = append(decls, function)
			}
		}
	}
	methods := map[string]bool{}
	for _, function := range decls {
		if function.Recv != nil {
			if ident, ok := function.Recv.List[0].Type.(*ast.Ident); ok && ident.Name == "Executor" {
				methods[function.Name.Name] = true
			}
		}
	}
	for _, function := range decls {
		name := function.Name.Name
		if function.Recv != nil {
			if ident, ok := function.Recv.List[0].Type.(*ast.Ident); !ok || ident.Name != "Executor" {
				name = "(other)." + name
			}
		} else {
			name = "(func)." + name
		}
		graph.walk(name, function.Body, methods)
	}
	return graph
}

func (g lockGraph) walk(name string, body ast.Node, methods map[string]bool) {
	inner := 0
	ast.Inspect(body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "updateNetwork" {
				for _, argument := range call.Args {
					if literal, ok := argument.(*ast.FuncLit); ok {
						inner++
						locked := name + ".locked" + strings.Repeat("'", inner)
						g.lockers[locked] = true
						g.walk(locked, literal.Body, methods)
						literal.Body = &ast.BlockStmt{}
					}
				}
			}
		}
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || !methods[selector.Sel.Name] {
			return true
		}
		switch selector.Sel.Name {
		case "lockNetwork":
			g.lockers[name] = true
		case "saveNetwork":
			g.saves[name] = true
		default:
			g.calls[name] = append(g.calls[name], selector.Sel.Name)
			g.called[selector.Sel.Name] = true
		}
		return true
	})
}

func (g lockGraph) reach(from string, stop func(string) bool) map[string][]string {
	paths := map[string][]string{from: {from}}
	queue := []string{from}
	for len(queue) > 0 {
		at := queue[0]
		queue = queue[1:]
		if at != from && stop(at) {
			continue
		}
		for _, next := range g.calls[at] {
			if _, seen := paths[next]; !seen {
				paths[next] = append(slices.Clone(paths[at]), next)
				queue = append(queue, next)
			}
		}
	}
	return paths
}

func TestTheNetworkLockIsNeverTakenTwiceInOneCallPath(t *testing.T) {
	graph := readLockGraph(t)
	for _, want := range []string{"applyLocked", "meet", "followExit", "retryRelayPorts", "holdMeetings", "release", "updateNetwork", "watchKnocks.locked'"} {
		if !graph.lockers[want] {
			t.Errorf("%s does not take the network lock", want)
		}
	}
	for locker := range graph.lockers {
		for at, path := range graph.reach(locker, func(string) bool { return false }) {
			if at != locker && graph.lockers[at] {
				t.Errorf("the lock is taken twice: %s", strings.Join(path, " → "))
			}
			if at == locker && len(path) > 1 {
				t.Errorf("a locker calls itself: %s", strings.Join(path, " → "))
			}
		}
	}
}

func TestEveryChangeToNetworkJSONHoldsTheLock(t *testing.T) {
	graph := readLockGraph(t)
	for start := range graph.calls {
		if graph.called[start] && !ast.IsExported(start) && !strings.HasPrefix(start, "(") {
			continue
		}
		for at, path := range graph.reach(start, func(at string) bool { return graph.lockers[at] }) {
			if graph.saves[at] && !graph.lockers[at] {
				t.Errorf("network.json is saved without the lock: %s", strings.Join(path, " → "))
			}
		}
	}
	for saver := range graph.saves {
		if !graph.called[saver] && !graph.lockers[saver] {
			t.Errorf("%s saves network.json without the lock", saver)
		}
	}
}
