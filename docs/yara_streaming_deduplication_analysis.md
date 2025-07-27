# YARA Match Deduplication in Streaming Mode - Analysis

## Executive Summary

This document analyzes the requirements and potential approaches for implementing YARA match deduplication in streaming mode, where rules should only trigger when a new stream contains new regex matches that weren't found in previous streams.

## Current Architecture Overview

### 1. Streaming Scanners

YARA-X provides two streaming scanner implementations:

1. **StreamingScanner**: Single-stream scanner that maintains state across multiple scans
2. **MultiStreamScanner**: Multi-stream scanner that manages multiple concurrent streams identified by UUID

### 2. Pattern Match Storage

Pattern matches are stored in the `Match` structure:

```rust
struct Match {
    range: Range<usize>,      // Start and end offset in data
    xor_key: Option<u8>,      // XOR key for XOR patterns
    trace_id: Option<String>, // Extracted trace ID from matched line
}
```

Key characteristics:
- Matches store only offset ranges, not actual matched data
- Trace IDs are extracted from matched lines (last quoted string)
- Offsets are adjusted for global stream position

### 3. Multi-Stream Context Management

Each stream maintains its own `StreamContext` containing:
- Pattern matches (HashMap<PatternId, MatchList>)
- Rule states (matching/non-matching)
- Bitmaps for WASM state preservation
- Statistics (bytes processed, lines counted)

### 4. Offset Cache

The offset cache (LevelDB-based) stores:
- Line data indexed by trace ID
- Allows offset-based data access across chunk boundaries
- LRU cache layer for frequently accessed data

## Deduplication Requirements

Based on the user's request, the deduplication should:

1. **Track unique matches per pattern**: Only trigger rules when NEW pattern matches are found
2. **Compare across streams**: Deduplicate matches that appeared in previous streams
3. **Consider match content**: Not just offsets, but actual matched strings/patterns
4. **Maintain performance**: Minimal overhead for streaming operations

## Analysis of Current Limitations

### 1. No Cross-Stream Match Tracking

Currently:
- Each stream maintains independent pattern matches
- No mechanism to compare matches across streams
- Rule evaluation is per-stream without global context

### 2. Match Storage Limitations

Current matches store:
- Offset ranges (not portable across streams)
- No actual matched content
- Trace IDs (helpful but not sufficient for deduplication)

### 3. Rule Triggering Logic

Current behavior:
- Rules trigger whenever all conditions are met
- No consideration of previous match history
- Each stream evaluation is independent

## Proposed Deduplication Approaches

### Approach 1: Content-Based Match Deduplication

**Key Idea**: Store hash of matched content for each pattern match

```rust
struct DeduplicatedMatch {
    pattern_id: PatternId,
    content_hash: u64,  // Hash of actual matched bytes
    trace_id: Option<String>,
    first_seen: Uuid,   // Stream where first seen
}
```

**Advantages**:
- Exact deduplication based on content
- Works across different offsets/streams
- Can use efficient hash-based lookups

**Disadvantages**:
- Requires storing/hashing matched content
- Additional memory overhead
- Need to extract matched bytes during scanning

### Approach 2: Pattern + Context Deduplication

**Key Idea**: Deduplicate based on pattern ID + surrounding context

```rust
struct ContextualMatch {
    pattern_id: PatternId,
    context_before: [u8; 32],  // Bytes before match
    context_after: [u8; 32],   // Bytes after match
    match_length: usize,
}
```

**Advantages**:
- Captures match uniqueness with context
- Fixed memory overhead
- Can handle slight variations

**Disadvantages**:
- May miss identical matches in different contexts
- Context extraction complexity
- Boundary handling issues

### Approach 3: Trace ID-Based Deduplication

**Key Idea**: Use trace IDs as deduplication keys

```rust
struct TraceBasedMatch {
    pattern_id: PatternId,
    trace_ids: HashSet<String>,  // Unique trace IDs seen
}
```

**Advantages**:
- Leverages existing trace ID extraction
- Simple implementation
- Natural fit for log analysis use cases

**Disadvantages**:
- Only works when trace IDs are present
- May miss matches without trace IDs
- Depends on trace ID uniqueness

### Approach 4: Hybrid Deduplication

**Key Idea**: Combine multiple strategies

```rust
struct HybridMatch {
    pattern_id: PatternId,
    content_hash: Option<u64>,
    trace_id: Option<String>,
    match_signature: Vec<u8>,  // Configurable signature
}
```

**Advantages**:
- Flexible deduplication strategies
- Can adapt to different use cases
- Fallback mechanisms

**Disadvantages**:
- More complex implementation
- Configuration overhead
- Performance considerations

## Implementation Considerations

### 1. Storage Requirements

For deduplication, we need to store:
- Global match history (across all streams)
- Efficient lookup structures (HashMap/HashSet)
- Persistence options (memory vs. disk)

### 2. Performance Impact

Key considerations:
- Hash computation overhead
- Memory growth with match history
- Lookup performance for deduplication checks

### 3. Configuration Options

Potential configuration:
- Deduplication strategy selection
- History retention policies
- Memory limits for match storage
- Per-rule deduplication settings

### 4. Integration Points

Where to implement deduplication:
1. **During pattern matching**: Check before adding to match list
2. **During rule evaluation**: Filter matches before condition evaluation
3. **Post-scan callback**: Deduplicate in match notification callbacks

## Recommended Approach

Based on the analysis, a **Hybrid Approach** with the following features is recommended:

1. **Primary Strategy**: Content-based hashing for exact deduplication
2. **Secondary Strategy**: Trace ID deduplication when available
3. **Configurable Behavior**: Per-rule or global deduplication settings
4. **Efficient Storage**: In-memory hash tables with optional persistence

### Implementation Steps

1. **Extend Match Structure**:
   ```rust
   struct Match {
       range: Range<usize>,
       xor_key: Option<u8>,
       trace_id: Option<String>,
       content_hash: Option<u64>,  // New field
   }
   ```

2. **Add Deduplication Manager**:
   ```rust
   struct DeduplicationManager {
       seen_matches: HashMap<(PatternId, u64), StreamId>,
       trace_id_matches: HashMap<(PatternId, String), StreamId>,
   }
   ```

3. **Modify Pattern Matching**:
   - Extract matched content during verification
   - Compute content hash
   - Check deduplication before adding match

4. **Update Rule Evaluation**:
   - Consider only "new" matches for rule conditions
   - Provide deduplication statistics

## Conclusion

Implementing YARA match deduplication in streaming mode requires:

1. **Storing match content** (or hashes) for comparison
2. **Cross-stream match tracking** infrastructure
3. **Configurable deduplication strategies**
4. **Performance optimization** for large-scale deployments

The recommended hybrid approach provides flexibility while maintaining performance, making it suitable for various use cases including log analysis, threat hunting, and continuous monitoring scenarios.