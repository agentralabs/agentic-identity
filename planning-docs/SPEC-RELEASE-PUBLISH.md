# SPEC-RELEASE-PUBLISH.md

## Required Platforms
- crates.io (MANDATORY)
- PyPI (MANDATORY)

## Release Workflow
1. Version bump in Cargo.toml
2. Update CHANGELOG.md
3. Run full test suite
4. Run stress tests
5. Build release binaries
6. Publish to crates.io
7. Build Python wheels
8. Publish to PyPI
9. Create GitHub release
10. Social broadcast (optional)

## Pre-Release Checklist
- [ ] All tests pass
- [ ] All stress tests pass
- [ ] cargo clippy clean
- [ ] cargo fmt check passes
- [ ] Documentation updated
- [ ] CHANGELOG updated
- [ ] Version numbers consistent

## Crates to Publish
1. agentic-identity (core)
2. agentic-identity-mcp (server)
3. agentic-identity-cli (binary)
4. agentic-identity-ffi (C bindings)

## PyPI Package
- Name: agentic-identity
- Includes: Python bindings via FFI
- Wheels for: Linux, macOS, Windows
