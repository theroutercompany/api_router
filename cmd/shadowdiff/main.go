package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/theroutercompany/api_router/internal/shadowdiff"
)

func main() {
	configPath := flag.String("config", "shadowdiff.config.json", "Path to shadow diff configuration")
	flag.Parse()

	cfg, err := shadowdiff.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	fixtures, err := shadowdiff.LoadFixtures(cfg.Fixtures)
	if err != nil {
		log.Fatalf("load fixtures: %v", err)
	}

	runner := shadowdiff.Runner{
		Config: cfg,
		Normalizers: []func([]byte) []byte{
			shadowdiff.StripJSONKeys("timestamp", "uptime", "checkedAt", "latencyMs"),
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results := runner.Run(ctx, fixtures)

	var diffCount int
	for _, result := range results {
		if result.Err != nil {
			fmt.Printf("[%s] error: %v\n", result.Fixture.Name, result.Err)
			continue
		}

		statusMatch := result.NodeStatus == result.GoStatus
		bodyMatch := result.BodyDiff == ""

		if !statusMatch || !bodyMatch {
			diffCount++
			fmt.Printf("[%s] status node=%d go=%d\n", result.Fixture.Name, result.NodeStatus, result.GoStatus)
			if result.BodyDiff != "" {
				fmt.Println(result.BodyDiff)
			}
		}
	}

	fmt.Printf("Processed %d fixtures, %d diffs found\n", len(results), diffCount)
}
