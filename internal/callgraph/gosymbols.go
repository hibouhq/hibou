package callgraph

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// GoReachableSymbols builds the module's call graph (VTA over SSA — the same
// analysis govulncheck uses) and returns every THIRD-PARTY symbol reachable
// from the module's own functions, qualified the way OSV declares vulnerable
// symbols: "import/path.Func" and "import/path.Type.Method".
//
// This is the durable half of Go reachability: govulncheck's verdicts cover
// the advisories known at CI time; this inventory is stored per snapshot so
// an advisory published LATER — with declared vulnerable symbols — gets a
// symbol-level verdict on frozen refs (releases, main) without a rebuild.
//
// this is SOURCE-mode analysis (SSA + VTA), the precise kind —
// govulncheck's documented "cannot show call graphs / may report false
// positives" caveat applies only to its binary mode (symbol-table-only, no
// call edges), which Hibou never uses. Two inherent limits remain, shared
// with govulncheck source mode: VTA is a sound over-approximation (rare
// extra "reachable" on exotic dynamic dispatch — the safe direction), and
// reflection-invoked calls (reflect.Value.Call) are not modeled.
func GoReachableSymbols(ctx context.Context, dir string) ([]string, error) {
	cfg := &packages.Config{
		Mode:    packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedDeps | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedModule,
		Dir:     dir,
		Context: ctx,
		Tests:   false,
	}
	loaded, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("load packages: %w", err)
	}
	if packages.PrintErrors(loaded) > 0 {
		return nil, fmt.Errorf("packages in %s did not load cleanly — the module must build", dir)
	}

	program, ssaPackages := ssautil.AllPackages(loaded, ssa.InstantiateGenerics)
	program.Build()

	// Own-module paths: their functions are the entry points (a library's
	// whole exported surface is callable), and their symbols are excluded
	// from the inventory (only third-party reachability matters here).
	ownPaths := map[string]bool{}
	for _, pkg := range loaded {
		ownPaths[pkg.PkgPath] = true
	}

	roots := []*ssa.Function{}
	for _, ssaPackage := range ssaPackages {
		if ssaPackage == nil {
			continue
		}
		for _, member := range ssaPackage.Members {
			if function, ok := member.(*ssa.Function); ok {
				roots = append(roots, function)
			}
		}
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("no functions found in %s", dir)
	}

	// VTA (variable type analysis) refined over a CHA baseline — precise on
	// interface dispatch, which is exactly where cheaper analyses (RTA) would
	// over-report and drown the inventory in never-called methods.
	graph := vta.CallGraph(ssautil.AllFunctions(program), cha.CallGraph(program))

	reachable := reachableFunctions(graph, roots)
	symbols := map[string]struct{}{}
	for function := range reachable {
		if function.Pkg == nil {
			continue
		}
		path := function.Pkg.Pkg.Path()
		if ownPaths[path] || isGoStdlib(path) {
			continue
		}
		if name := qualifiedGoSymbol(path, function); name != "" {
			symbols[name] = struct{}{}
		}
	}

	out := make([]string, 0, len(symbols))
	for symbol := range symbols {
		out = append(out, symbol)
	}
	sort.Strings(out)
	return out, nil
}

// reachableFunctions walks the call graph from the module's own functions.
func reachableFunctions(graph *callgraph.Graph, roots []*ssa.Function) map[*ssa.Function]struct{} {
	visited := map[*ssa.Function]struct{}{}
	queue := []*callgraph.Node{}
	for _, root := range roots {
		if node := graph.Nodes[root]; node != nil {
			visited[root] = struct{}{}
			queue = append(queue, node)
		}
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		for _, edge := range node.Out {
			callee := edge.Callee
			if callee == nil || callee.Func == nil {
				continue
			}
			if _, seen := visited[callee.Func]; seen {
				continue
			}
			visited[callee.Func] = struct{}{}
			queue = append(queue, callee)
		}
	}
	return visited
}

// qualifiedGoSymbol renders a function the way OSV symbol lists do:
// "path.Func" for functions, "path.Type.Method" for methods (pointer
// receivers included under the bare type name).
func qualifiedGoSymbol(path string, function *ssa.Function) string {
	if function.Parent() != nil {
		return "" // anonymous/closure — OSV never names these
	}
	if recv := function.Signature.Recv(); recv != nil {
		typeName := recv.Type().String()
		typeName = strings.TrimPrefix(typeName, "*")
		if dot := strings.LastIndex(typeName, "."); dot >= 0 {
			typeName = typeName[dot+1:]
		}
		// Drop generic instantiation brackets: Type[T] → Type.
		if bracket := strings.Index(typeName, "["); bracket >= 0 {
			typeName = typeName[:bracket]
		}
		return path + "." + typeName + "." + function.Name()
	}
	return path + "." + function.Name()
}

// isGoStdlib: standard-library import paths have no dot in their first
// segment ("fmt", "net/http"); module paths do ("github.com/…").
func isGoStdlib(path string) bool {
	first := path
	if slash := strings.Index(path, "/"); slash >= 0 {
		first = path[:slash]
	}
	return !strings.Contains(first, ".")
}
