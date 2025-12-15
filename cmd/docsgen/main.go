package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type annotationText struct {
	What  string `yaml:"what"`
	How   string `yaml:"how"`
	Why   string `yaml:"why"`
	Notes string `yaml:"notes"`
}

type fileAnnotations struct {
	File     string                    `yaml:"file"`
	Title    string                    `yaml:"title"`
	Overview annotationText            `yaml:"overview"`
	Symbols  map[string]annotationText `yaml:"symbols"`
}

type symbolEntry struct {
	ID      string
	Heading string
}

type declBlock struct {
	Label     string
	Kind      string
	StartLine int
	Snippet   string
	Symbols   []symbolEntry
}

type funcEntry struct {
	ID        string
	Heading   string
	StartLine int
	Snippet   string
	Steps     []walkStep
}

type walkStep struct {
	StartLine int
	Code      string
	What      string
	Why       string
	How       string
	Children  []walkStep
}

type walkthroughConfig struct {
	Enabled  bool
	MaxDepth int
	MaxSteps int
}

type fileDoc struct {
	SrcPath        string
	OutPath        string
	AnnotationPath string
	Title          string
	PackageName    string
	Overview       annotationText
	Blocks         []declBlock
	Funcs          []funcEntry
}

func main() {
	var (
		repoRoot      = flag.String("repo", ".", "repo root")
		outDir        = flag.String("out", "docs/docs/annotated", "output directory for generated mdx files")
		annotationDir = flag.String("annotations", "docs/annotations", "directory for per-file annotation yaml")
		githubBase    = flag.String("github-base", "https://github.com/theroutercompany/api_router/blob/main/", "base URL for source links")
		initAnn       = flag.Bool("init-annotations", false, "create/update annotation yaml stubs for the generated files")
		walkthrough   = flag.Bool("walkthrough", true, "include statement-by-statement walkthroughs for functions/methods")
		walkMaxDepth  = flag.Int("walkthrough-max-depth", 6, "maximum nesting depth for walkthrough output")
		walkMaxSteps  = flag.Int("walkthrough-max-steps", 500, "maximum number of walkthrough steps per function/method")
	)
	flag.Parse()

	files := coreFiles()
	if len(flag.Args()) > 0 {
		files = flag.Args()
	}

	var errs []error
	walkCfg := walkthroughConfig{
		Enabled:  *walkthrough,
		MaxDepth: *walkMaxDepth,
		MaxSteps: *walkMaxSteps,
	}
	for _, rel := range files {
		if err := generateFile(*repoRoot, *outDir, *annotationDir, *githubBase, rel, *initAnn, walkCfg); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		for _, err := range errs {
			fmt.Fprintf(os.Stderr, "docsgen error: %v\n", err)
		}
		os.Exit(1)
	}
}

func coreFiles() []string {
	return []string{
		"cmd/apigw/main.go",
		"cmd/docsgen/main.go",
		"cmd/gateway/main.go",
		"cmd/openapi/main.go",

		"cmd/shadowdiff/main.go",

		"internal/openapi/service.go",
		"internal/platform/health/health.go",
		"internal/service/placeholder.go",
		"internal/shadowdiff/config.go",
		"internal/shadowdiff/diff.go",
		"internal/shadowdiff/fixture.go",
		"internal/shadowdiff/normalize.go",

		"examples/basic/main.go",

		"pkg/gateway/auth/authenticator.go",
		"pkg/gateway/config/config.go",
		"pkg/gateway/daemon/daemon.go",
		"pkg/gateway/metrics/registry.go",
		"pkg/gateway/problem/problem.go",
		"pkg/gateway/proxy/reverse_proxy.go",
		"pkg/gateway/proxy/testdata/graphql_stream_server.go",
		"pkg/gateway/proxy/testdata/sse_server.go",
		"pkg/gateway/runtime/runtime.go",
		"pkg/gateway/server/middleware/middleware.go",
		"pkg/gateway/server/protocol_metrics.go",
		"pkg/gateway/server/ratelimiter.go",
		"pkg/gateway/server/request_metadata.go",
		"pkg/gateway/server/server.go",
		"pkg/gateway/webhook/handler.go",

		"pkg/log/logger.go",
	}
}

func generateFile(repoRoot, outDir, annotationDir, githubBase, relSrcPath string, initAnnotations bool, walkCfg walkthroughConfig) error {
	srcPath := filepath.Join(repoRoot, filepath.Clean(relSrcPath))
	srcBytes, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", relSrcPath, err)
	}

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, srcPath, srcBytes, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("parse %s: %w", relSrcPath, err)
	}

	annPath := filepath.Join(repoRoot, annotationDir, replaceExt(relSrcPath, ".yaml"))
	blocks := extractBlocks(fset, parsed, srcBytes)
	funcs := extractFuncs(fset, parsed, srcBytes, walkCfg)
	if initAnnotations {
		if err := ensureAnnotationFile(annPath, relSrcPath, blocks, funcs); err != nil {
			return fmt.Errorf("init annotations %s: %w", annPath, err)
		}
	}
	anns, err := loadAnnotations(annPath)
	if err != nil {
		return fmt.Errorf("load annotations %s: %w", annPath, err)
	}

	title := anns.Title
	if strings.TrimSpace(title) == "" {
		title = relSrcPath
	}

	outPath := filepath.Join(repoRoot, outDir, replaceExt(relSrcPath, ".mdx"))
	doc := fileDoc{
		SrcPath:        relSrcPath,
		OutPath:        outPath,
		AnnotationPath: filepath.ToSlash(filepath.Join(annotationDir, replaceExt(relSrcPath, ".yaml"))),
		Title:          title,
		PackageName:    parsed.Name.Name,
		Overview:       anns.Overview,
	}

	doc.Blocks = append(doc.Blocks, blocks...)
	doc.Funcs = append(doc.Funcs, funcs...)

	sort.SliceStable(doc.Blocks, func(i, j int) bool { return doc.Blocks[i].StartLine < doc.Blocks[j].StartLine })
	sort.SliceStable(doc.Funcs, func(i, j int) bool { return doc.Funcs[i].StartLine < doc.Funcs[j].StartLine })

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(outPath), err)
	}

	content := render(doc, anns, githubBase)
	if err := os.WriteFile(outPath, content, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	return nil
}

func loadAnnotations(path string) (fileAnnotations, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fileAnnotations{Symbols: map[string]annotationText{}}, nil
		}
		return fileAnnotations{}, err
	}
	var anns fileAnnotations
	if err := yaml.Unmarshal(data, &anns); err != nil {
		return fileAnnotations{}, err
	}
	if anns.Symbols == nil {
		anns.Symbols = map[string]annotationText{}
	}
	return anns, nil
}

func replaceExt(path, ext string) string {
	base := strings.TrimSuffix(path, filepath.Ext(path))
	return filepath.ToSlash(base) + ext
}

func extractBlocks(fset *token.FileSet, file *ast.File, src []byte) []declBlock {
	var blocks []declBlock
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		switch gen.Tok {
		case token.IMPORT:
			blocks = append(blocks, buildGenDeclBlock(fset, gen, src, "Imports", "import"))
		case token.CONST:
			blocks = append(blocks, buildGenDeclBlock(fset, gen, src, "Constants", "const"))
		case token.VAR:
			blocks = append(blocks, buildGenDeclBlock(fset, gen, src, "Variables", "var"))
		case token.TYPE:
			blocks = append(blocks, buildGenDeclBlock(fset, gen, src, "Types", "type"))
		}
	}
	return blocks
}

func buildGenDeclBlock(fset *token.FileSet, gen *ast.GenDecl, src []byte, sectionLabel, kind string) declBlock {
	startLine := fset.Position(gen.Pos()).Line
	snippet := sliceSource(fset, src, gen.Pos(), gen.End())

	var symbols []symbolEntry
	for _, spec := range gen.Specs {
		switch s := spec.(type) {
		case *ast.ValueSpec:
			for _, name := range s.Names {
				id := fmt.Sprintf("%s %s", kind, name.Name)
				symbols = append(symbols, symbolEntry{
					ID:      id,
					Heading: fmt.Sprintf("`%s`", name.Name),
				})
			}
		case *ast.TypeSpec:
			id := fmt.Sprintf("%s %s", kind, s.Name.Name)
			symbols = append(symbols, symbolEntry{
				ID:      id,
				Heading: fmt.Sprintf("`%s`", s.Name.Name),
			})
		}
	}

	return declBlock{
		Label:     sectionLabel,
		Kind:      kind,
		StartLine: startLine,
		Snippet:   snippet,
		Symbols:   symbols,
	}
}

func extractFuncs(fset *token.FileSet, file *ast.File, src []byte, walkCfg walkthroughConfig) []funcEntry {
	var entries []funcEntry
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}

		startLine := fset.Position(fn.Pos()).Line
		snippet := sliceSource(fset, src, fn.Pos(), fn.End())
		steps := []walkStep(nil)
		if walkCfg.Enabled {
			steps = extractWalkthroughSteps(fset, src, fn, walkCfg)
		}

		id := fmt.Sprintf("func %s", fn.Name.Name)
		heading := fmt.Sprintf("`%s`", fn.Name.Name)
		if fn.Recv != nil && len(fn.Recv.List) > 0 {
			recv := receiverTypeString(fset, fn.Recv.List[0].Type)
			id = fmt.Sprintf("method (%s).%s", recv, fn.Name.Name)
			heading = fmt.Sprintf("`(%s).%s`", recv, fn.Name.Name)
		}

		entries = append(entries, funcEntry{
			ID:        id,
			Heading:   heading,
			StartLine: startLine,
			Snippet:   snippet,
			Steps:     steps,
		})
	}
	return entries
}

func extractWalkthroughSteps(fset *token.FileSet, src []byte, fn *ast.FuncDecl, cfg walkthroughConfig) []walkStep {
	if fn == nil || fn.Body == nil || len(fn.Body.List) == 0 || cfg.MaxSteps <= 0 {
		return nil
	}

	steps := make([]walkStep, 0, len(fn.Body.List))
	count := 0
	for _, stmt := range fn.Body.List {
		if stmt == nil || count >= cfg.MaxSteps {
			break
		}
		step, ok := walkStmt(fset, src, stmt, 0, cfg, &count)
		if ok {
			steps = append(steps, step)
		}
	}
	if count >= cfg.MaxSteps {
		steps = append(steps, walkStep{
			StartLine: fset.Position(fn.End()).Line,
			Code:      "(walkthrough truncated)",
			What:      "Walkthrough output was truncated.",
			Why:       "Keeps pages readable and avoids generating excessively large MDX output by default.",
			How:       "Re-run docsgen with a higher `-walkthrough-max-steps` value to include more steps.",
		})
	}
	return steps
}

func walkStmt(fset *token.FileSet, src []byte, stmt ast.Stmt, depth int, cfg walkthroughConfig, count *int) (walkStep, bool) {
	if stmt == nil || count == nil || *count >= cfg.MaxSteps {
		return walkStep{}, false
	}

	startLine := fset.Position(stmt.Pos()).Line
	code := condenseSnippet(sliceSource(fset, src, stmt.Pos(), stmt.End()))
	what, why, how := describeStmt(fset, stmt)
	step := walkStep{
		StartLine: startLine,
		Code:      code,
		What:      what,
		Why:       why,
		How:       how,
	}
	*count++
	if *count >= cfg.MaxSteps || depth >= cfg.MaxDepth {
		return step, true
	}

	appendChild := func(child walkStep) {
		if *count >= cfg.MaxSteps {
			return
		}
		step.Children = append(step.Children, child)
	}
	appendChildren := func(children []walkStep) {
		for _, child := range children {
			if *count >= cfg.MaxSteps {
				return
			}
			step.Children = append(step.Children, child)
		}
	}

	switch s := stmt.(type) {
	case *ast.BlockStmt:
		appendChildren(walkStmtList(fset, src, s.List, depth+1, cfg, count))
		return step, true

	case *ast.LabeledStmt:
		if s.Stmt != nil {
			if child, ok := walkStmt(fset, src, s.Stmt, depth+1, cfg, count); ok {
				appendChild(child)
			}
		}
		return step, true

	case *ast.IfStmt:
		if s.Init != nil {
			if child, ok := walkStmt(fset, src, s.Init, depth+1, cfg, count); ok {
				appendChild(child)
			}
		}
		appendChildren(walkStmtList(fset, src, s.Body.List, depth+1, cfg, count))
		switch elseNode := s.Else.(type) {
		case *ast.BlockStmt:
			appendChildren(walkStmtList(fset, src, elseNode.List, depth+1, cfg, count))
		case ast.Stmt:
			if child, ok := walkStmt(fset, src, elseNode, depth+1, cfg, count); ok {
				appendChild(child)
			}
		}
		appendChildren(walkFuncLitsFromExpr(fset, src, s.Cond, depth+1, cfg, count))
		return step, true

	case *ast.ForStmt:
		if s.Init != nil {
			if child, ok := walkStmt(fset, src, s.Init, depth+1, cfg, count); ok {
				appendChild(child)
			}
		}
		if s.Post != nil {
			if child, ok := walkStmt(fset, src, s.Post, depth+1, cfg, count); ok {
				appendChild(child)
			}
		}
		appendChildren(walkStmtList(fset, src, s.Body.List, depth+1, cfg, count))
		appendChildren(walkFuncLitsFromExpr(fset, src, s.Cond, depth+1, cfg, count))
		return step, true

	case *ast.RangeStmt:
		appendChildren(walkStmtList(fset, src, s.Body.List, depth+1, cfg, count))
		appendChildren(walkFuncLitsFromExpr(fset, src, s.X, depth+1, cfg, count))
		return step, true

	case *ast.SwitchStmt:
		if s.Init != nil {
			if child, ok := walkStmt(fset, src, s.Init, depth+1, cfg, count); ok {
				appendChild(child)
			}
		}
		appendChildren(walkFuncLitsFromExpr(fset, src, s.Tag, depth+1, cfg, count))
		for _, raw := range s.Body.List {
			cc, ok := raw.(*ast.CaseClause)
			if !ok || *count >= cfg.MaxSteps {
				break
			}
			caseStep, ok := walkCaseClause(fset, src, cc, depth+1, cfg, count)
			if ok {
				appendChild(caseStep)
			}
		}
		return step, true

	case *ast.TypeSwitchStmt:
		if s.Init != nil {
			if child, ok := walkStmt(fset, src, s.Init, depth+1, cfg, count); ok {
				appendChild(child)
			}
		}
		if s.Assign != nil {
			if child, ok := walkStmt(fset, src, s.Assign, depth+1, cfg, count); ok {
				appendChild(child)
			}
		}
		for _, raw := range s.Body.List {
			cc, ok := raw.(*ast.CaseClause)
			if !ok || *count >= cfg.MaxSteps {
				break
			}
			caseStep, ok := walkCaseClause(fset, src, cc, depth+1, cfg, count)
			if ok {
				appendChild(caseStep)
			}
		}
		return step, true

	case *ast.SelectStmt:
		for _, raw := range s.Body.List {
			cl, ok := raw.(*ast.CommClause)
			if !ok || *count >= cfg.MaxSteps {
				break
			}
			caseStep, ok := walkCommClause(fset, src, cl, depth+1, cfg, count)
			if ok {
				appendChild(caseStep)
			}
		}
		return step, true

	case *ast.AssignStmt:
		for _, expr := range s.Rhs {
			appendChildren(walkFuncLitsFromExpr(fset, src, expr, depth+1, cfg, count))
		}
		return step, true

	case *ast.ReturnStmt:
		for _, expr := range s.Results {
			appendChildren(walkFuncLitsFromExpr(fset, src, expr, depth+1, cfg, count))
		}
		return step, true

	case *ast.ExprStmt:
		appendChildren(walkFuncLitsFromExpr(fset, src, s.X, depth+1, cfg, count))
		return step, true

	case *ast.GoStmt:
		if s.Call != nil {
			appendChildren(walkFuncLitsFromExpr(fset, src, s.Call, depth+1, cfg, count))
		}
		return step, true

	case *ast.DeferStmt:
		if s.Call != nil {
			appendChildren(walkFuncLitsFromExpr(fset, src, s.Call, depth+1, cfg, count))
		}
		return step, true

	default:
		return step, true
	}
}

func walkStmtList(fset *token.FileSet, src []byte, list []ast.Stmt, depth int, cfg walkthroughConfig, count *int) []walkStep {
	if len(list) == 0 || count == nil || *count >= cfg.MaxSteps {
		return nil
	}
	out := make([]walkStep, 0, len(list))
	for _, stmt := range list {
		if stmt == nil || *count >= cfg.MaxSteps {
			break
		}
		step, ok := walkStmt(fset, src, stmt, depth, cfg, count)
		if ok {
			out = append(out, step)
		}
	}
	return out
}

func walkFuncLitsFromExpr(fset *token.FileSet, src []byte, expr ast.Expr, depth int, cfg walkthroughConfig, count *int) []walkStep {
	if expr == nil || count == nil || *count >= cfg.MaxSteps {
		return nil
	}
	lits := funcLitsInExpr(expr)
	if len(lits) == 0 {
		return nil
	}
	out := make([]walkStep, 0, len(lits))
	for _, lit := range lits {
		if lit == nil || *count >= cfg.MaxSteps {
			break
		}
		step, ok := walkFuncLit(fset, src, lit, depth, cfg, count)
		if ok {
			out = append(out, step)
		}
	}
	return out
}

func walkFuncLit(fset *token.FileSet, src []byte, lit *ast.FuncLit, depth int, cfg walkthroughConfig, count *int) (walkStep, bool) {
	if lit == nil || count == nil || *count >= cfg.MaxSteps {
		return walkStep{}, false
	}

	startLine := fset.Position(lit.Pos()).Line
	code := condenseSnippet(sliceSource(fset, src, lit.Pos(), lit.End()))
	step := walkStep{
		StartLine: startLine,
		Code:      code,
		What:      "Defines an inline function (closure).",
		Why:       "Encapsulates callback logic and may capture variables from the surrounding scope.",
		How:       "Declares a `func` literal and uses it as a value (for example, as an HTTP handler or callback).",
	}
	*count++
	if *count >= cfg.MaxSteps || depth >= cfg.MaxDepth || lit.Body == nil || len(lit.Body.List) == 0 {
		return step, true
	}

	step.Children = append(step.Children, walkStmtList(fset, src, lit.Body.List, depth+1, cfg, count)...)
	return step, true
}

func walkCaseClause(fset *token.FileSet, src []byte, clause *ast.CaseClause, depth int, cfg walkthroughConfig, count *int) (walkStep, bool) {
	if clause == nil || count == nil || *count >= cfg.MaxSteps {
		return walkStep{}, false
	}

	startLine := fset.Position(clause.Pos()).Line
	var head string
	if len(clause.List) == 0 {
		head = "default:"
	} else {
		var parts []string
		for _, expr := range clause.List {
			parts = append(parts, strings.TrimSpace(nodeString(fset, expr)))
		}
		head = "case " + strings.Join(parts, ", ") + ":"
	}

	step := walkStep{
		StartLine: startLine,
		Code:      condenseSnippet(head),
		What:      "Selects a switch case.",
		Why:       "Makes multi-branch control flow explicit and readable.",
		How:       "Runs this case body when the switch value matches (or when default is selected).",
	}
	*count++
	if *count >= cfg.MaxSteps || depth >= cfg.MaxDepth || len(clause.Body) == 0 {
		return step, true
	}
	step.Children = append(step.Children, walkStmtList(fset, src, clause.Body, depth+1, cfg, count)...)
	return step, true
}

func walkCommClause(fset *token.FileSet, src []byte, clause *ast.CommClause, depth int, cfg walkthroughConfig, count *int) (walkStep, bool) {
	if clause == nil || count == nil || *count >= cfg.MaxSteps {
		return walkStep{}, false
	}

	startLine := fset.Position(clause.Pos()).Line
	head := "default:"
	if clause.Comm != nil {
		head = "case " + strings.TrimSpace(nodeString(fset, clause.Comm)) + ":"
	}

	step := walkStep{
		StartLine: startLine,
		Code:      condenseSnippet(head),
		What:      "Selects a select-case branch.",
		Why:       "Coordinates concurrent operations without blocking incorrectly.",
		How:       "Runs this case body when its channel operation is ready (or runs default immediately).",
	}
	*count++
	if *count >= cfg.MaxSteps || depth >= cfg.MaxDepth || len(clause.Body) == 0 {
		return step, true
	}
	step.Children = append(step.Children, walkStmtList(fset, src, clause.Body, depth+1, cfg, count)...)
	return step, true
}

func funcLitsInExpr(expr ast.Expr) []*ast.FuncLit {
	if expr == nil {
		return nil
	}
	var lits []*ast.FuncLit
	ast.Inspect(expr, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		lit, ok := n.(*ast.FuncLit)
		if !ok {
			return true
		}
		lits = append(lits, lit)
		return false
	})
	return lits
}

func describeStmt(fset *token.FileSet, stmt ast.Stmt) (what, why, how string) {
	switch s := stmt.(type) {
	case *ast.AssignStmt:
		names := strings.TrimSpace(exprListString(fset, s.Lhs))
		if names == "" {
			names = "value(s)"
		}
		if s.Tok == token.DEFINE {
			what = fmt.Sprintf("Defines %s.", names)
		} else {
			what = fmt.Sprintf("Assigns %s.", names)
		}
		why = "Keeps intermediate state available for later steps in the function."
		how = "Evaluates the right-hand side expressions and stores results in the left-hand variables."
		return what, why, how

	case *ast.DeclStmt:
		what = "Declares local names."
		why = "Introduces variables or types used later in the function."
		how = "Executes a Go declaration statement inside the function body."
		return what, why, how

	case *ast.IfStmt:
		what = "Branches conditionally."
		if isGuardIf(s) {
			why = "Short-circuits early when a precondition is not met or an error/edge case is detected."
		} else {
			why = "Handles different execution paths based on runtime state."
		}
		how = "Evaluates the condition and executes the matching branch."
		return what, why, how

	case *ast.ReturnStmt:
		what = "Returns from the current function."
		why = "Ends the current execution path and hands control back to the caller."
		how = "Executes a `return` statement (possibly returning values)."
		return what, why, how

	case *ast.ExprStmt:
		if call, ok := s.X.(*ast.CallExpr); ok {
			callee := strings.TrimSpace(nodeString(fset, call.Fun))
			if callee != "" {
				what = fmt.Sprintf("Calls %s.", callee)
			} else {
				what = "Calls a function."
			}
		} else {
			what = "Evaluates an expression."
		}
		why = "Performs side effects or delegates work to a helper."
		how = "Executes the expression statement."
		return what, why, how

	case *ast.ForStmt:
		what = "Runs a loop."
		why = "Repeats logic until a condition is met or the loop terminates."
		how = "Executes a `for` loop statement."
		return what, why, how

	case *ast.RangeStmt:
		what = "Iterates over a collection."
		why = "Processes multiple elements with the same logic."
		how = "Executes a `for ... range` loop."
		return what, why, how

	case *ast.SwitchStmt:
		what = "Selects a branch from multiple cases."
		why = "Keeps multi-case branching readable and explicit."
		how = "Evaluates the switch expression and executes the first matching case."
		return what, why, how

	case *ast.TypeSwitchStmt:
		what = "Selects a branch based on dynamic type."
		why = "Handles multiple concrete types cleanly."
		how = "Executes a type switch statement."
		return what, why, how

	case *ast.SelectStmt:
		what = "Selects among concurrent operations."
		why = "Coordinates channel operations without blocking incorrectly."
		how = "Executes a `select` statement and runs one ready case."
		return what, why, how

	case *ast.SendStmt:
		what = "Sends a value on a channel."
		why = "Communicates with another goroutine."
		how = "Executes a channel send operation."
		return what, why, how

	case *ast.DeferStmt:
		what = "Defers a call for cleanup."
		why = "Ensures the deferred action runs even on early returns."
		how = "Schedules the call to run when the surrounding function returns."
		return what, why, how

	case *ast.GoStmt:
		what = "Starts a goroutine."
		why = "Runs work concurrently."
		how = "Invokes the function call asynchronously using `go`."
		return what, why, how

	case *ast.IncDecStmt:
		what = "Updates a counter."
		why = "Maintains an index or tally used by subsequent logic."
		how = "Executes an increment/decrement statement."
		return what, why, how

	default:
		what = "Executes a statement."
		why = "Advances the function logic."
		how = "Runs this statement as part of the function body."
		return what, why, how
	}
}

func isGuardIf(stmt *ast.IfStmt) bool {
	if stmt == nil || stmt.Else != nil || stmt.Body == nil || len(stmt.Body.List) == 0 {
		return false
	}
	for _, s := range stmt.Body.List {
		if _, ok := s.(*ast.ReturnStmt); ok {
			return true
		}
	}
	return false
}

func ensureAnnotationFile(path string, relSrcPath string, blocks []declBlock, funcs []funcEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	anns, err := loadAnnotations(path)
	if err != nil {
		return err
	}

	if strings.TrimSpace(anns.File) == "" {
		anns.File = relSrcPath
	}
	if strings.TrimSpace(anns.Title) == "" {
		anns.Title = relSrcPath
	}
	if anns.Symbols == nil {
		anns.Symbols = map[string]annotationText{}
	}

	var ids []string
	for _, block := range blocks {
		for _, sym := range block.Symbols {
			ids = append(ids, sym.ID)
		}
	}
	for _, fn := range funcs {
		ids = append(ids, fn.ID)
	}
	sort.Strings(ids)

	for _, id := range ids {
		if _, ok := anns.Symbols[id]; !ok {
			anns.Symbols[id] = annotationText{}
		}
	}

	out, err := marshalAnnotations(anns)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

func marshalAnnotations(anns fileAnnotations) ([]byte, error) {
	root := &yaml.Node{Kind: yaml.MappingNode}

	appendKV(root, "file", yamlStringNode(anns.File))
	appendKV(root, "title", yamlStringNode(anns.Title))

	overview := &yaml.Node{Kind: yaml.MappingNode}
	appendKV(overview, "what", yamlStringNode(anns.Overview.What))
	appendKV(overview, "why", yamlStringNode(anns.Overview.Why))
	appendKV(overview, "how", yamlStringNode(anns.Overview.How))
	appendKV(overview, "notes", yamlStringNode(anns.Overview.Notes))
	appendKV(root, "overview", overview)

	symbols := &yaml.Node{Kind: yaml.MappingNode}
	keys := make([]string, 0, len(anns.Symbols))
	for key := range anns.Symbols {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		val := anns.Symbols[key]
		entry := &yaml.Node{Kind: yaml.MappingNode}
		appendKV(entry, "what", yamlStringNode(val.What))
		appendKV(entry, "why", yamlStringNode(val.Why))
		appendKV(entry, "how", yamlStringNode(val.How))
		appendKV(entry, "notes", yamlStringNode(val.Notes))
		appendKV(symbols, key, entry)
	}
	appendKV(root, "symbols", symbols)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func appendKV(node *yaml.Node, key string, value *yaml.Node) {
	node.Content = append(node.Content, &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: key,
	}, value)
}

func yamlStringNode(value string) *yaml.Node {
	value = strings.TrimSpace(value)
	node := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: value,
	}
	if strings.Contains(value, "\n") {
		node.Style = yaml.LiteralStyle
	}
	return node
}

func receiverTypeString(fset *token.FileSet, expr ast.Expr) string {
	var buf bytes.Buffer
	_ = printer.Fprint(&buf, fset, expr)
	return strings.TrimSpace(buf.String())
}

func nodeString(fset *token.FileSet, node any) string {
	var buf bytes.Buffer
	_ = printer.Fprint(&buf, fset, node)
	return strings.TrimSpace(buf.String())
}

func exprListString(fset *token.FileSet, exprs []ast.Expr) string {
	if len(exprs) == 0 {
		return ""
	}
	var parts []string
	for _, expr := range exprs {
		parts = append(parts, strings.TrimSpace(nodeString(fset, expr)))
	}
	return strings.Join(parts, ", ")
}

func sliceSource(fset *token.FileSet, src []byte, start, end token.Pos) string {
	file := fset.File(start)
	if file == nil {
		return ""
	}
	startOff := file.Offset(start)
	endOff := file.Offset(end)
	if startOff < 0 || endOff < 0 || startOff >= len(src) || endOff > len(src) || startOff >= endOff {
		return ""
	}
	return strings.TrimRight(string(src[startOff:endOff]), "\n")
}

func condenseSnippet(src string) string {
	out := strings.TrimSpace(src)
	if out == "" {
		return out
	}
	out = strings.ReplaceAll(out, "\r\n", "\n")
	out = strings.ReplaceAll(out, "\n", " ")
	out = strings.Join(strings.Fields(out), " ")
	return truncateRunes(out, 140)
}

func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 1 {
		return string(r[:max])
	}
	return string(r[:max-1]) + "…"
}

func markdownInlineCode(src string) string {
	if strings.TrimSpace(src) == "" {
		return "`(empty)`"
	}
	maxRun := 0
	curRun := 0
	for _, r := range src {
		if r == '`' {
			curRun++
			if curRun > maxRun {
				maxRun = curRun
			}
		} else {
			curRun = 0
		}
	}
	delim := strings.Repeat("`", maxRun+1)
	if maxRun == 0 {
		return "`" + src + "`"
	}
	return delim + " " + src + " " + delim
}

func render(doc fileDoc, anns fileAnnotations, githubBase string) []byte {
	var buf bytes.Buffer

	fmt.Fprintf(&buf, "---\n")
	fmt.Fprintf(&buf, "title: %q\n", doc.Title)
	fmt.Fprintf(&buf, "---\n\n")

	fmt.Fprintf(&buf, "<!--\n")
	fmt.Fprintf(&buf, "Generated by `go run ./cmd/docsgen`.\n")
	fmt.Fprintf(&buf, "Do not edit this file directly.\n")
	fmt.Fprintf(&buf, "Edit commentary in `%s`.\n", doc.AnnotationPath)
	fmt.Fprintf(&buf, "-->\n\n")

	fmt.Fprintf(&buf, "## Source\n\n")
	fmt.Fprintf(&buf, "- Package: `%s`\n", doc.PackageName)
	fmt.Fprintf(&buf, "- File: `%s`\n", doc.SrcPath)
	fmt.Fprintf(&buf, "- GitHub: %s%s\n\n", githubBase, doc.SrcPath)

	overview := doc.Overview
	if strings.TrimSpace(overview.What) == "" && strings.TrimSpace(overview.How) == "" && strings.TrimSpace(overview.Why) == "" {
		overview.What = "This page documents the declarations in this file."
		overview.How = "Use the sections below to jump to the symbol you care about, then follow the links back to source."
		overview.Why = "These docs exist to make onboarding and code review faster by explaining intent, not just mechanics."
	}

	fmt.Fprintf(&buf, "## Overview\n\n")
	writeWhatHowWhy(&buf, overview)

	sectionOrder := []string{"Imports", "Constants", "Variables", "Types"}
	blocksBySection := map[string][]declBlock{}
	for _, block := range doc.Blocks {
		blocksBySection[block.Label] = append(blocksBySection[block.Label], block)
	}

	for _, section := range sectionOrder {
		blocks := blocksBySection[section]
		if len(blocks) == 0 {
			continue
		}
		fmt.Fprintf(&buf, "\n## %s\n\n", section)
		for i, block := range blocks {
			fmt.Fprintf(&buf, "### `%s` block %d\n\n", block.Kind, i+1)
			fmt.Fprintf(&buf, "```go title=%q showLineNumbers\n%s\n```\n\n", fmt.Sprintf("%s#L%d", doc.SrcPath, block.StartLine), block.Snippet)

			for _, sym := range block.Symbols {
				fmt.Fprintf(&buf, "#### %s\n\n", sym.Heading)
				writeWhatHowWhy(&buf, resolveSymbol(anns, sym.ID))
			}
		}
	}

	if len(doc.Funcs) > 0 {
		fmt.Fprintf(&buf, "\n## Functions and Methods\n\n")
		for _, fn := range doc.Funcs {
			fmt.Fprintf(&buf, "### %s\n\n", fn.Heading)
			writeWhatHowWhy(&buf, resolveSymbol(anns, fn.ID))
			fmt.Fprintf(&buf, "```go title=%q showLineNumbers\n%s\n```\n\n", fmt.Sprintf("%s#L%d", doc.SrcPath, fn.StartLine), fn.Snippet)
			writeWalkthrough(&buf, fn.Steps)
		}
	}

	return buf.Bytes()
}

func writeWalkthrough(buf *bytes.Buffer, steps []walkStep) {
	if len(steps) == 0 {
		return
	}

	fmt.Fprintf(buf, "#### Walkthrough\n\n")
	fmt.Fprintf(buf, "The list below documents the statements inside the function body, including nested blocks and inline closures.\n\n")
	writeWalkthroughSteps(buf, steps, 0)
	fmt.Fprintf(buf, "\n")
}

func writeWalkthroughSteps(buf *bytes.Buffer, steps []walkStep, depth int) {
	indent := strings.Repeat("  ", depth)
	for _, step := range steps {
		code := strings.TrimSpace(step.Code)
		if code == "" {
			code = "(unavailable)"
		}

		fmt.Fprintf(buf, "%s- **L%d**: %s\n", indent, step.StartLine, markdownInlineCode(code))
		fmt.Fprintf(buf, "%s  - **What:** %s\n", indent, strings.TrimSpace(step.What))
		fmt.Fprintf(buf, "%s  - **Why:** %s\n", indent, strings.TrimSpace(step.Why))
		fmt.Fprintf(buf, "%s  - **How:** %s\n", indent, strings.TrimSpace(step.How))
		if len(step.Children) > 0 {
			fmt.Fprintf(buf, "%s  - **Nested steps:**\n", indent)
			writeWalkthroughSteps(buf, step.Children, depth+2)
		}
	}
}

func resolveSymbol(anns fileAnnotations, id string) annotationText {
	if anns.Symbols == nil {
		return annotationText{
			What: fmt.Sprintf("Declare `%s`.", id),
			How:  "See the Go snippet and the source link for behavior and usage.",
			Why:  "Centralizes behavior and avoids duplication in call sites.",
		}
	}
	if val, ok := anns.Symbols[id]; ok {
		if strings.TrimSpace(val.What) == "" {
			val.What = fmt.Sprintf("Declare `%s`.", id)
		}
		if strings.TrimSpace(val.How) == "" {
			val.How = "See the Go snippet and the source link for behavior and usage."
		}
		if strings.TrimSpace(val.Why) == "" {
			val.Why = "Centralizes behavior and avoids duplication in call sites."
		}
		return val
	}
	return annotationText{
		What: fmt.Sprintf("Declare `%s`.", id),
		How:  "See the Go snippet and the source link for behavior and usage.",
		Why:  "Centralizes behavior and avoids duplication in call sites.",
	}
}

func writeWhatHowWhy(buf *bytes.Buffer, t annotationText) {
	writeLabeledText(buf, "What", t.What)
	writeLabeledText(buf, "Why", t.Why)
	writeLabeledText(buf, "How", t.How)
	if strings.TrimSpace(t.Notes) != "" {
		writeLabeledText(buf, "Notes", t.Notes)
	}
}

func writeLabeledText(buf *bytes.Buffer, label string, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		fmt.Fprintf(buf, "**%s:**\n\n\n", label)
		return
	}

	// When the value contains lists or multiple paragraphs, keep the label on its own line
	// so markdown list markers can render correctly.
	if strings.Contains(value, "\n") || strings.HasPrefix(value, "- ") || strings.HasPrefix(value, "* ") || looksLikeOrderedList(value) {
		fmt.Fprintf(buf, "**%s:**\n\n%s\n\n", label, value)
		return
	}
	fmt.Fprintf(buf, "**%s:** %s\n\n", label, value)
}

func looksLikeOrderedList(value string) bool {
	if value == "" {
		return false
	}
	i := 0
	for i < len(value) && value[i] >= '0' && value[i] <= '9' {
		i++
	}
	if i == 0 || i >= len(value) {
		return false
	}
	if value[i] != '.' {
		return false
	}
	if i+1 >= len(value) {
		return false
	}
	return value[i+1] == ' ' || value[i+1] == '\t'
}
