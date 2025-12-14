# Release Process

Tagged releases are built automatically via the GitHub Actions workflow in
`.github/workflows/release.yml` using GoReleaser.

## Cutting a Release

1. Ensure `main` is green (`go test ./...`, lint, CI passing).
2. Update `CHANGELOG.md` or release notes (if desired).
3. Tag the release (e.g. `git tag v0.1.0 && git push origin v0.1.0`).
4. The GitHub Actions workflow will:
   - Run the test suite.
   - Build platform-specific archives (`linux`/`darwin` x86_64 & arm64).
   - Publish the release artifacts and checksums using GoReleaser.

The release is marked as pre-release automatically when the tag contains
prerelease identifiers (e.g. `-beta`).

Generated artifacts appear in the GitHub release along with a checksums file.
