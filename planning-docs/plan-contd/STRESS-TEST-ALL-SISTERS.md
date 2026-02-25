# Comprehensive Stress Testing — All 4 Sisters

> **Goal:** Validate Memory + Vision + Codebase + Identity work together under heavy load and edge cases

---

## Test Matrix

```
SISTERS TO TEST
───────────────
Memory    — .amem graphs, cognitive events, queries
Vision    — .avis captures, comparisons, diffs
Codebase  — .acb graphs, impact analysis, prophecy
Identity  — .aid files, receipts, trust, continuity, spawn

INTEGRATION POINTS
──────────────────
Memory ↔ Identity  — Signed memory nodes, memory receipts
Vision ↔ Identity  — Signed captures, visual evidence
Codebase ↔ Identity — Signed analysis, attributed predictions
All ↔ Identity     — Every sister action can be receipted
```

---

## Stress Test Categories

### Category 1: Scale Tests

```python
# test_scale.py

def test_memory_100k_nodes():
    """Memory graph with 100,000 nodes."""
    graph = MemoryGraph()
    for i in range(100_000):
        graph.add_fact(f"Fact {i}", confidence=0.9)
    assert graph.node_count == 100_000
    # Query should complete in < 100ms
    start = time.time()
    results = graph.query_by_type("fact", limit=100)
    assert time.time() - start < 0.1

def test_vision_10k_captures():
    """Vision graph with 10,000 captures."""
    graph = VisionGraph()
    for i in range(10_000):
        graph.capture(f"https://example.com/page{i}")
    assert graph.capture_count == 10_000
    # Query should complete in < 50ms
    
def test_codebase_50k_units():
    """Codebase graph with 50,000 code units."""
    # Use a large real codebase or generate synthetic
    graph = CodebaseGraph()
    graph.compile("/path/to/large/project")
    assert graph.unit_count >= 50_000
    # Impact analysis should complete in < 500ms

def test_identity_100k_receipts():
    """Identity with 100,000 receipts in chain."""
    identity = Identity.create("stress-test")
    for i in range(100_000):
        identity.sign_action(f"Action {i}")
    # Chain verification should complete in < 5s
    
def test_identity_10k_experiences():
    """Continuity chain with 10,000 experiences."""
    identity = Identity.create("continuity-test")
    for i in range(10_000):
        identity.record_experience(ExperienceType.Cognition, f"hash{i}")
    # Continuity proof should complete in < 1s

def test_spawn_tree_1000_nodes():
    """Spawn tree with 1,000 descendants."""
    root = Identity.create("root")
    # Create tree of depth 5, branching factor ~4
    def spawn_tree(parent, depth):
        if depth == 0:
            return
        for i in range(4):
            child = parent.spawn(SpawnType.Worker, f"child-{depth}-{i}")
            spawn_tree(child, depth - 1)
    spawn_tree(root, 5)  # 4^5 = 1024 descendants
    # Lineage verification should complete in < 2s
```

### Category 2: Concurrency Tests

```python
# test_concurrency.py

def test_concurrent_memory_writes():
    """50 threads writing to same memory graph."""
    graph = MemoryGraph("shared.amem")
    errors = []
    
    def writer(thread_id):
        try:
            for i in range(100):
                graph.add_fact(f"Thread {thread_id} fact {i}")
        except Exception as e:
            errors.append(e)
    
    threads = [Thread(target=writer, args=(i,)) for i in range(50)]
    for t in threads: t.start()
    for t in threads: t.join()
    
    assert len(errors) == 0
    assert graph.node_count == 5000

def test_concurrent_identity_signing():
    """50 threads signing with same identity."""
    identity = Identity.create("concurrent-signer")
    receipts = []
    lock = Lock()
    
    def signer(thread_id):
        for i in range(100):
            receipt = identity.sign_action(f"Thread {thread_id} action {i}")
            with lock:
                receipts.append(receipt)
    
    threads = [Thread(target=signer, args=(i,)) for i in range(50)]
    for t in threads: t.start()
    for t in threads: t.join()
    
    # All receipts should be valid and chain should be consistent
    assert len(receipts) == 5000
    # Verify chain integrity
    identity.verify_chain()

def test_concurrent_trust_verification():
    """100 threads verifying trust simultaneously."""
    grantor = Identity.create("grantor")
    grantee = Identity.create("grantee")
    grant = grantor.trust_grant(grantee.id, "calendar:*")
    
    results = []
    def verifier():
        for _ in range(100):
            result = grantee.verify_trust("calendar:events:read")
            results.append(result)
    
    threads = [Thread(target=verifier) for _ in range(100)]
    for t in threads: t.start()
    for t in threads: t.join()
    
    assert all(r.is_valid for r in results)

def test_concurrent_mcp_servers():
    """4 MCP servers (one per sister) handling concurrent requests."""
    # Start all 4 MCP servers
    # Send 100 requests to each simultaneously
    # Verify all succeed without deadlock
    pass
```

### Category 3: Edge Cases

```python
# test_edge_cases.py

# === MEMORY EDGE CASES ===

def test_memory_empty_graph_queries():
    """Query empty graph returns empty, not error."""
    graph = MemoryGraph()
    assert graph.query_by_type("fact") == []
    assert graph.query_recent(10) == []
    
def test_memory_unicode_content():
    """Memory handles unicode correctly."""
    graph = MemoryGraph()
    graph.add_fact("用户喜欢Python 🐍")
    graph.add_fact("مرحبا بالعالم")
    result = graph.query_recent(2)
    assert len(result) == 2

def test_memory_very_long_content():
    """Memory handles 1MB content."""
    graph = MemoryGraph()
    content = "x" * (1024 * 1024)  # 1MB
    graph.add_fact(content)
    result = graph.query_recent(1)
    assert len(result[0].content) == 1024 * 1024

def test_memory_special_characters():
    """Memory handles special characters."""
    graph = MemoryGraph()
    graph.add_fact("Content with\nnewlines\tand\ttabs")
    graph.add_fact('Content with "quotes" and \'apostrophes\'')
    graph.add_fact("Content with <xml> & {json}")

# === VISION EDGE CASES ===

def test_vision_invalid_url():
    """Vision handles invalid URLs gracefully."""
    graph = VisionGraph()
    with pytest.raises(ValueError):
        graph.capture("not-a-url")

def test_vision_unreachable_url():
    """Vision handles unreachable URLs."""
    graph = VisionGraph()
    # Should fail gracefully, not hang
    with pytest.raises(ConnectionError):
        graph.capture("https://definitely-not-a-real-domain-12345.com")

def test_vision_duplicate_captures():
    """Vision handles duplicate URLs."""
    graph = VisionGraph()
    id1 = graph.capture("https://example.com")
    id2 = graph.capture("https://example.com")
    # Should create two separate captures (timestamps differ)
    assert id1 != id2

# === CODEBASE EDGE CASES ===

def test_codebase_empty_project():
    """Codebase handles empty project."""
    graph = CodebaseGraph()
    graph.compile("/tmp/empty-project")
    assert graph.unit_count == 0

def test_codebase_circular_dependencies():
    """Codebase handles circular deps without infinite loop."""
    # Create project with A -> B -> C -> A
    graph = CodebaseGraph()
    graph.compile("/tmp/circular-project")
    # Should complete, not hang

def test_codebase_binary_files():
    """Codebase ignores binary files."""
    graph = CodebaseGraph()
    graph.compile("/tmp/project-with-binaries")
    # Should not crash on binary content

# === IDENTITY EDGE CASES ===

def test_identity_expired_trust():
    """Verify fails for expired trust."""
    grantor = Identity.create("grantor")
    grantee = Identity.create("grantee")
    grant = grantor.trust_grant(grantee.id, "calendar:*", expires_in=1)  # 1 second
    time.sleep(2)
    result = grantee.verify_trust("calendar:events:read")
    assert not result.is_valid
    assert "expired" in result.errors[0].lower()

def test_identity_revoked_trust():
    """Verify fails for revoked trust."""
    grantor = Identity.create("grantor")
    grantee = Identity.create("grantee")
    grant = grantor.trust_grant(grantee.id, "calendar:*")
    grantor.trust_revoke(grant.id)
    result = grantee.verify_trust("calendar:events:read")
    assert not result.is_valid

def test_identity_capability_wildcard_matching():
    """Wildcard capability matching works correctly."""
    grantor = Identity.create("grantor")
    grantee = Identity.create("grantee")
    grant = grantor.trust_grant(grantee.id, "calendar:*:*")
    
    assert grantee.verify_trust("calendar:events:read").is_valid
    assert grantee.verify_trust("calendar:events:write").is_valid
    assert grantee.verify_trust("calendar:reminders:create").is_valid
    assert not grantee.verify_trust("email:inbox:read").is_valid

def test_identity_spawn_authority_bounding():
    """Child cannot exceed parent authority."""
    parent = Identity.create("parent", ceiling=["calendar:*", "email:read"])
    
    # This should fail - deploy not in parent's ceiling
    with pytest.raises(AuthorityError):
        parent.spawn(SpawnType.Worker, "bad-child", authority=["deploy:*"])
    
    # This should succeed
    child = parent.spawn(SpawnType.Worker, "good-child", authority=["calendar:events:read"])
    assert child.verify_trust("calendar:events:read").is_valid
    assert not child.verify_trust("deploy:production:execute").is_valid

def test_identity_spawn_depth_limit():
    """Spawn depth limit enforced."""
    root = Identity.create("root")
    current = root
    
    # Default depth limit is usually 10
    for i in range(10):
        current = current.spawn(SpawnType.Worker, f"child-{i}")
    
    # 11th spawn should fail
    with pytest.raises(SpawnDepthError):
        current.spawn(SpawnType.Worker, "too-deep")

def test_identity_continuity_gap_detection():
    """Gap detection finds temporal gaps."""
    identity = Identity.create("gapper")
    
    # Record experiences with a gap
    identity.record_experience(ExperienceType.Cognition, "hash1")
    time.sleep(2)  # 2 second gap
    identity.record_experience(ExperienceType.Cognition, "hash2")
    
    gaps = identity.detect_gaps(grace_period=1)  # 1 second grace
    assert len(gaps) == 1
    assert gaps[0].gap_type == GapType.Temporal

def test_identity_chain_tampering_detection():
    """Tampering with receipt chain is detected."""
    identity = Identity.create("tamper-test")
    identity.sign_action("Action 1")
    identity.sign_action("Action 2")
    identity.sign_action("Action 3")
    
    # Manually tamper with chain (simulated)
    # This would require direct file manipulation
    # Verification should fail

def test_identity_wrong_key_verification():
    """Verification with wrong key fails."""
    identity1 = Identity.create("signer")
    identity2 = Identity.create("other")
    
    receipt = identity1.sign_action("My action")
    
    # Verify with wrong public key should fail
    result = receipt.verify_with_key(identity2.public_key)
    assert not result.is_valid
```

### Category 4: Cross-Sister Integration

```python
# test_integration.py

def test_signed_memory_nodes():
    """Memory nodes signed by identity."""
    identity = Identity.create("memory-signer")
    graph = MemoryGraph()
    
    # Add fact and sign it
    node_id = graph.add_fact("Important fact")
    receipt = identity.sign_action(
        ActionType.MemoryOperation,
        data={"operation": "store", "node_id": node_id}
    )
    
    # Verify signature
    assert receipt.verify().is_valid

def test_signed_vision_captures():
    """Vision captures signed by identity."""
    identity = Identity.create("vision-signer")
    graph = VisionGraph()
    
    capture_id = graph.capture("https://example.com")
    receipt = identity.sign_action(
        ActionType.Observation,
        data={"source": "vision", "capture_id": capture_id}
    )
    
    assert receipt.verify().is_valid

def test_signed_codebase_analysis():
    """Codebase analysis results signed by identity."""
    identity = Identity.create("code-analyst")
    graph = CodebaseGraph()
    graph.compile("/path/to/project")
    
    impact = graph.impact_analysis("src/main.rs")
    receipt = identity.sign_action(
        ActionType.Decision,
        data={"analysis": "impact", "result_hash": hash(str(impact))}
    )
    
    assert receipt.verify().is_valid

def test_all_sisters_workflow():
    """Complete workflow using all 4 sisters."""
    # 1. Create identity
    agent = Identity.create("full-workflow-agent")
    
    # 2. Capture web page
    vision = VisionGraph()
    capture_id = vision.capture("https://github.com/example/repo")
    agent.sign_action(ActionType.Observation, {"capture": capture_id})
    
    # 3. Analyze codebase
    codebase = CodebaseGraph()
    codebase.compile("/path/to/repo")
    impact = codebase.impact_analysis("src/main.rs")
    agent.sign_action(ActionType.Decision, {"impact": str(impact)})
    
    # 4. Store memory
    memory = MemoryGraph()
    memory.add_fact(f"Analyzed repo, impact score: {impact['score']}")
    agent.sign_action(ActionType.MemoryOperation, {"operation": "store"})
    
    # 5. Verify entire chain
    chain_valid = agent.verify_chain()
    assert chain_valid.is_valid
    assert chain_valid.receipt_count == 3

def test_spawned_agent_uses_sisters():
    """Spawned agent with limited authority uses sisters."""
    parent = Identity.create("parent", ceiling=["memory:*", "vision:*"])
    child = parent.spawn(
        SpawnType.Worker, 
        "reader",
        authority=["memory:facts:read", "vision:captures:read"]
    )
    
    # Child can read
    memory = MemoryGraph()
    memory.add_fact("Test fact")
    # child.sign_action(...) should work for reads
    
    # Child cannot write (not in authority)
    # Attempting to sign write action should fail trust verification
```

### Category 5: Recovery and Resilience

```python
# test_resilience.py

def test_corrupted_file_detection():
    """Corrupted .amem/.avis/.acb/.aid files detected."""
    # Create valid file
    graph = MemoryGraph()
    graph.add_fact("Test")
    graph.save("test.amem")
    
    # Corrupt it
    with open("test.amem", "r+b") as f:
        f.seek(100)
        f.write(b"CORRUPTED")
    
    # Load should fail with clear error
    with pytest.raises(CorruptedFileError):
        MemoryGraph.load("test.amem")

def test_process_crash_recovery():
    """Recovery after simulated crash during write."""
    # Start write operation
    # Kill process mid-write (simulated)
    # Recovery should either:
    #   a) Complete the write (if atomic)
    #   b) Roll back to last good state
    pass

def test_stale_lock_recovery():
    """Stale lock files are cleaned up."""
    # Create stale lock (old timestamp)
    # Open should succeed after recovery
    pass

def test_version_migration():
    """Old file format versions can be read."""
    # Create v1 format file
    # New code should read it and optionally upgrade
    pass
```

---

## Benchmark Targets

```
SCALE TARGETS
─────────────
Memory 100K nodes:     Load < 2s, Query < 100ms
Vision 10K captures:   Load < 5s, Query < 50ms
Codebase 50K units:    Load < 10s, Impact < 500ms
Identity 100K receipts: Load < 5s, Verify < 5s
Continuity 10K exp:    Proof < 1s
Spawn 1K descendants:  Lineage < 2s

CONCURRENCY TARGETS
───────────────────
50 concurrent writes:  No deadlock, No data loss
100 concurrent reads:  < 2x single-thread latency
4 MCP servers:         No resource conflicts
```

---

## Test Execution Order

```bash
# 1. Unit tests (each sister independently)
cd agentic-memory && cargo test
cd agentic-vision && cargo test
cd agentic-codebase && cargo test
cd agentic-identity && cargo test

# 2. Scale tests
pytest tests/stress/test_scale.py -v

# 3. Concurrency tests
pytest tests/stress/test_concurrency.py -v

# 4. Edge case tests
pytest tests/stress/test_edge_cases.py -v

# 5. Integration tests
pytest tests/stress/test_integration.py -v

# 6. Resilience tests
pytest tests/stress/test_resilience.py -v

# 7. Full benchmark suite
pytest tests/stress/ --benchmark-only
```

---

## Success Criteria

```
[ ] All 4 sisters pass unit tests independently
[ ] Scale tests meet benchmark targets
[ ] No deadlocks in concurrency tests
[ ] All edge cases handled gracefully
[ ] Cross-sister integration works
[ ] Recovery mechanisms function
[ ] All tests pass on: Linux, macOS, Windows
[ ] Python packages importable together
[ ] MCP servers can run simultaneously
```
