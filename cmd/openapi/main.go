package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/theroutercompany/api_router/internal/openapi"
)

func main() {
	outPath := flag.String("out", "dist/openapi.json", "Path to write the merged OpenAPI document")
	flag.Parse()

	svc := openapi.NewService(openapi.WithDistPath(*outPath))

	if _, err := svc.Document(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "openapi merge failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stdout, "OpenAPI document written to %s\n", *outPath)
}
