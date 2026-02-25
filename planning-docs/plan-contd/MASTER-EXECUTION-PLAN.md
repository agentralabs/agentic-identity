# Master Execution Plan — Complete & Publish 4 Sisters

> **Goal:** Finish all work, test thoroughly, publish together, close out

---

## Current State

```
SISTER          RUST      PYPI      MCP       TESTS     COMPLETE
────────────────────────────────────────────────────────────────
Memory          ✅        ✅        ✅        ✅        ✅
Vision          ✅        ❌        ✅        ✅        ❌
Codebase        ✅        ❌        ✅        ✅        ❌
Identity        ✅        ❌        ✅        196       ❌ (3/5 inv)
```

---

## Execution Phases

### Phase 1: Complete Identity v0.1 (Inventions 4 & 5)

**Input:** IDENTITY-V01-COMPLETION.md
**Owner:** Claude Code
**Duration:** ~16-20 hours

```
Tasks:
├── Add src/continuity/ module
│   ├── Types: ExperienceEvent, ContinuityState, Anchor, Heartbeat, Claim, Gap
│   ├── Engine: record_experience, create_anchor, create_heartbeat, verify
│   └── Tests: 16 scenarios
│
├── Add src/spawn/ module
│   ├── Types: SpawnRecord, SpawnType, Lifetime, Constraints, Lineage
│   ├── Engine: spawn_child, terminate, verify_lineage, effective_authority
│   └── Tests: 16 scenarios
│
├── CLI additions
│   ├── aid continuity [record|anchor|heartbeat|prove|verify|status|gaps]
│   └── aid spawn [create|list|terminate|lineage|children|ancestors|authority]
│
├── MCP additions
│   ├── Tools: continuity_*, spawn_*
│   └── Resources: continuity://, experiences://, spawn://, lineage://
│
└── Integration
    ├── Connect continuity to receipts (ContinuityBinding)
    ├── Connect spawn to identity (IdentityType::Spawned)
    └── Connect spawn to trust (authority ceiling)

Success: cargo test --all passes with 228+ tests
```

### Phase 2: PyPI Backfill (Vision + Codebase)

**Input:** PYPI-BACKFILL-VISION-CODEBASE.md
**Owner:** Claude Code
**Duration:** ~4-6 hours

```
Vision:
├── Create python/ directory
├── Add pyproject.toml
├── Add src/agentic_vision/__init__.py
├── Add src/agentic_vision/_ffi.py
├── Add src/agentic_vision/vision.py
├── Verify FFI function signatures match C API
├── Add tests/test_vision.py
├── Build wheel: python -m build
└── Test: pip install dist/*.whl && python -c "import agentic_vision"

Codebase:
├── Create python/ directory
├── Add pyproject.toml
├── Add src/agentic_codebase/__init__.py
├── Add src/agentic_codebase/_ffi.py
├── Add src/agentic_codebase/codebase.py
├── Verify FFI function signatures match C API
├── Add tests/test_codebase.py
├── Build wheel: python -m build
└── Test: pip install dist/*.whl && python -c "import agentic_codebase"

Success: Both packages importable, basic operations work
```

### Phase 3: Comprehensive Stress Testing

**Input:** STRESS-TEST-ALL-SISTERS.md
**Owner:** Claude Code
**Duration:** ~6-8 hours

```
Test Categories:
├── Scale Tests
│   ├── Memory 100K nodes
│   ├── Vision 10K captures
│   ├── Codebase 50K units
│   ├── Identity 100K receipts
│   ├── Continuity 10K experiences
│   └── Spawn 1K descendants
│
├── Concurrency Tests
│   ├── 50 concurrent writers
│   ├── 100 concurrent readers
│   ├── Concurrent signing
│   └── 4 MCP servers
│
├── Edge Cases
│   ├── Empty graphs
│   ├── Unicode content
│   ├── Very large content
│   ├── Invalid inputs
│   ├── Expired/revoked trust
│   ├── Authority bounding
│   ├── Spawn depth limits
│   └── Gap detection
│
├── Integration Tests
│   ├── Signed memory nodes
│   ├── Signed vision captures
│   ├── Signed codebase analysis
│   ├── Full workflow (all 4)
│   └── Spawned agent workflow
│
└── Resilience Tests
    ├── Corrupted file detection
    ├── Crash recovery
    ├── Stale lock recovery
    └── Version migration

Success: All tests pass, benchmarks meet targets
```

### Phase 4: Publish All

**Duration:** ~2-3 hours

```
Pre-publish checklist:
├── All tests pass (Rust + Python)
├── cargo clippy clean
├── cargo fmt clean
├── Documentation complete
├── CHANGELOG updated
├── Version numbers consistent

Publish order:
1. agentic-identity → crates.io
2. agentic-identity → PyPI
3. agentic-vision → PyPI (backfill)
4. agentic-codebase → PyPI (backfill)

Verification:
├── cargo install agentic-identity-cli
├── pip install agentic-memory agentic-vision agentic-codebase agentic-identity
└── Run integration test script
```

### Phase 5: Post-Publish Validation

**Duration:** ~2-3 hours

```
Tests:
├── Fresh install on clean machine
├── Import all 4 packages
├── Run basic operations each
├── Run integration workflow
├── Verify MCP servers work

Platforms:
├── Linux (Ubuntu 22.04)
├── macOS (M1/M2)
└── Windows 11
```

---

## Timeline

```
PHASE                           DURATION    CUMULATIVE
───────────────────────────────────────────────────────
1. Complete Identity v0.1       16-20h      16-20h
2. PyPI Backfill               4-6h        20-26h
3. Stress Testing              6-8h        26-34h
4. Publish All                 2-3h        28-37h
5. Post-Publish Validation     2-3h        30-40h
───────────────────────────────────────────────────────
TOTAL                          30-40 hours
```

---

## Claude Code Tasks (Sequential)

### Task 1: Identity Completion

```
Complete AgenticIdentity v0.1 per IDENTITY-V01-COMPLETION.md

Add Temporal Continuity (Invention 4):
- Create src/continuity/ module
- Implement all types and engine functions
- Add CLI commands: aid continuity *
- Add MCP tools: continuity_*
- Write 16 tests

Add Identity Inheritance (Invention 5):
- Create src/spawn/ module  
- Implement all types and engine functions
- Add CLI commands: aid spawn *
- Add MCP tools: spawn_*
- Write 16 tests

Run: cargo test --all
Target: 228+ tests passing
```

### Task 2: PyPI Backfill

```
Add Python packages to Vision and Codebase per PYPI-BACKFILL-VISION-CODEBASE.md

Vision:
- Create python/ package structure
- Implement FFI bindings
- Write tests
- Verify with: python -c "import agentic_vision"

Codebase:
- Create python/ package structure
- Implement FFI bindings
- Write tests
- Verify with: python -c "import agentic_codebase"
```

### Task 3: Stress Testing

```
Run comprehensive stress tests per STRESS-TEST-ALL-SISTERS.md

Execute:
- Scale tests
- Concurrency tests
- Edge case tests
- Integration tests
- Resilience tests

Fix any failures before proceeding.
```

### Task 4: Publish

```
Publish all packages:

1. cargo publish -p agentic-identity
2. cargo publish -p agentic-identity-cli
3. cargo publish -p agentic-identity-mcp
4. twine upload agentic-identity/python/dist/*
5. twine upload agentic-vision/python/dist/*
6. twine upload agentic-codebase/python/dist/*
```

### Task 5: Post-Publish Validation

```
Verify published packages work:

pip install agentic-memory agentic-vision agentic-codebase agentic-identity

python -c "
import agentic_memory
import agentic_vision
import agentic_codebase
import agentic_identity

print('Memory:', agentic_memory.__version__)
print('Vision:', agentic_vision.__version__)
print('Codebase:', agentic_codebase.__version__)
print('Identity:', agentic_identity.__version__)
print('All sisters imported successfully!')
"
```

---

## Final State

```
After completion:

SISTER          RUST      PYPI      MCP       TESTS     INVENTIONS
─────────────────────────────────────────────────────────────────
Memory          ✅        ✅        ✅        ✅        6/6 events
Vision          ✅        ✅        ✅        ✅        Full
Codebase        ✅        ✅        ✅        ✅        Full
Identity        ✅        ✅        ✅        228+      5/5 v0.1

Status: CLOSED ✅
Next: AgenticTime or AgenticContract
```

---

## Files Created

| File | Purpose |
|------|---------|
| IDENTITY-V01-COMPLETION.md | Spec for adding Continuity + Inheritance |
| PYPI-BACKFILL-VISION-CODEBASE.md | Spec for Python packages |
| STRESS-TEST-ALL-SISTERS.md | Comprehensive test scenarios |
| MASTER-EXECUTION-PLAN.md | This file - overall plan |
