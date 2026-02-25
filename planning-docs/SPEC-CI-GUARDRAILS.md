# SPEC-CI-GUARDRAILS.md

## Required CI Checks

### On Every PR
- cargo test --all
- cargo clippy -- -D warnings
- cargo fmt --check
- cargo doc --no-deps

### On Release
- All PR checks
- Stress tests (--ignored)
- Cross-platform build
- Install command verification
- MCP config merge test

## Guardrail Scripts

### check-install-commands.sh
- Verify install script syntax
- Test on fresh environment
- Verify MCP config merge (not overwrite)

### check-canonical-sister.sh
- Verify all hardening requirements met
- Check per-project isolation
- Verify strict MCP validation
- Check concurrent safety

### test-primary-problems.sh
- Multi-project isolation test
- Same-name folder test
- Concurrent startup test
- Restart continuity test
- Server auth test

## CI Workflow Files
- ci.yml: Main CI (runs on all PRs)
- release.yml: Release workflow
- install-command-guardrails.yml: Install verification
- canonical-sister-guardrails.yml: Sister compliance

## Failure = Block
All guardrail failures MUST block merge/release.
