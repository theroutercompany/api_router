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
	)
	flag.Parse()

	files := coreFiles()
	if len(flag.Args()) > 0 {
		files = flag.Args()
	}

	var errs []error
	for _, rel := range files {
		if err := generateFile(*repoRoot, *outDir, *annotationDir, *githubBase, rel, *initAnn); err != nil {
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
		"cmd/gateway/main.go",
		"cmd/openapi/main.go",

		"internal/openapi/service.go",
		"internal/platform/health/health.go",

		"pkg/gateway/auth/authenticator.go",
		"pkg/gateway/config/config.go",
		"pkg/gateway/daemon/daemon.go",
		"pkg/gateway/metrics/registry.go",
		"pkg/gateway/problem/problem.go",
		"pkg/gateway/proxy/reverse_proxy.go",
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

func generateFile(repoRoot, outDir, annotationDir, githubBase, relSrcPath string, initAnnotations bool) error {
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
	funcs := extractFuncs(fset, parsed, srcBytes)
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

func extractFuncs(fset *token.FileSet, file *ast.File, src []byte) []funcEntry {
	var entries []funcEntry
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}

		startLine := fset.Position(fn.Pos()).Line
		snippet := sliceSource(fset, src, fn.Pos(), fn.End())

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
		})
	}
	return entries
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
		}
	}

	return buf.Bytes()
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
	fmt.Fprintf(buf, "**What:** %s\n\n", strings.TrimSpace(t.What))
	fmt.Fprintf(buf, "**Why:** %s\n\n", strings.TrimSpace(t.Why))
	fmt.Fprintf(buf, "**How:** %s\n\n", strings.TrimSpace(t.How))
	if strings.TrimSpace(t.Notes) != "" {
		fmt.Fprintf(buf, "**Notes:** %s\n\n", strings.TrimSpace(t.Notes))
	}
}
