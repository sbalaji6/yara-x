# Multi-Stream Scanner Analysis for YARA-X

## Overview

This document analyzes different approaches for implementing multi-stream support in YARA-X's streaming scanner, where each stream is identified by a UUID and maintains independent scanning state.

## Requirements

1. Support multiple concurrent streams identified by UUID
2. Efficiently switch between streams without losing state
3. Preserve all accumulated state per stream (pattern matches, rule evaluations, offsets, counters)
4. Memory-efficient implementation for handling many concurrent streams
5. Thread-safe if concurrent access is needed

## Approach 1: HashMap of StreamingScanner Instances

### Concept
Maintain a HashMap where each UUID maps to a complete `StreamingScanner` instance.

```rust
pub struct MultiStreamScanner<'r> {
    rules: &'r Rules,
    streams: HashMap<Uuid, StreamingScanner<'r>>,
}

impl<'r> MultiStreamScanner<'r> {
    pub fn scan_chunk(&mut self, stream_id: Uuid, chunk: &[u8]) -> Result<(), ScanError> {
        let scanner = self.streams.entry(stream_id)
            .or_insert_with(|| StreamingScanner::new(self.rules));
        scanner.scan_chunk(chunk)
    }
}
```

### Pros
- **Simple implementation**: Direct and easy to understand
- **Complete isolation**: Each stream has its own scanner instance
- **No state management complexity**: Scanner handles its own state
- **Easy stream lifecycle**: Just add/remove from HashMap

### Cons
- **High memory usage**: Each scanner has:
  - WASM store (~MB size)
  - WASM instance
  - Module initialization data
  - Pattern match structures
- **Expensive scanner creation**: WASM initialization is costly
- **Resource duplication**: Multiple copies of identical WASM resources
- **Poor scalability**: Memory grows linearly with stream count

### Memory Estimate
For N streams: ~N × (WASM_STORE_SIZE + INSTANCE_SIZE + STATE_SIZE)

## Approach 2: State Serialization/Deserialization

### Concept
Use a single `StreamingScanner` and serialize/deserialize state when switching streams.

```rust
#[derive(Serialize, Deserialize)]
pub struct StreamState {
    pattern_matches: PatternMatches,
    matching_rules: Vec<RuleId>,
    global_offset: u64,
    line_count: u64,
    module_outputs: HashMap<String, Vec<u8>>, // Serialized outputs
}

pub struct MultiStreamScanner<'r> {
    scanner: StreamingScanner<'r>,
    states: HashMap<Uuid, StreamState>,
    active_stream: Option<Uuid>,
}

impl<'r> MultiStreamScanner<'r> {
    pub fn scan_chunk(&mut self, stream_id: Uuid, chunk: &[u8]) -> Result<(), ScanError> {
        // Save current state if different stream
        if self.active_stream != Some(stream_id) {
            self.save_current_state()?;
            self.load_stream_state(stream_id)?;
        }
        self.scanner.scan_chunk(chunk)
    }
}
```

### Pros
- **Single WASM instance**: Minimal resource duplication
- **Lower memory footprint**: Only active stream in memory
- **Persistence capability**: Can save states to disk
- **Bounded memory usage**: Can implement LRU eviction

### Cons
- **Serialization overhead**: Cost of save/restore on stream switch
- **Complex state management**: Must track all mutable state
- **Module output serialization**: Complex for dynamic messages
- **Error-prone**: Easy to miss state components
- **No concurrent scanning**: Only one active stream at a time

### Performance Impact
Stream switch time: O(STATE_SIZE) for serialization + deserialization

## Approach 3: Modified StreamingScanner with Stream Context (Recommended)

### Concept
Share WASM resources while maintaining separate state contexts per stream.

```rust
pub struct StreamContext {
    pattern_matches: PatternMatches,
    non_private_matching_rules: Vec<RuleId>,
    private_matching_rules: Vec<RuleId>,
    matching_rules: IndexMap<u32, Vec<RuleId>>,
    unconfirmed_matches: FxHashMap<SubPatternId, Vec<UnconfirmedMatch>>,
    limit_reached: FxHashSet<PatternId>,
    total_bytes_processed: u64,
    line_count: u64,
    module_outputs: FxHashMap<String, Box<dyn MessageDyn>>,
}

pub struct MultiStreamScanner<'r> {
    rules: &'r Rules,
    wasm_store: Pin<Box<Store<ScanContext<'static>>>>,
    wasm_main_func: TypedFunc<(), i32>,
    wasm_instance: wasmtime::Instance,
    filesize: Global,
    pattern_search_done: Global,
    contexts: HashMap<Uuid, StreamContext>,
    active_stream: Option<Uuid>,
    timeout: Option<Duration>,
}

impl<'r> MultiStreamScanner<'r> {
    pub fn scan_chunk(&mut self, stream_id: Uuid, chunk: &[u8]) -> Result<(), ScanError> {
        self.switch_to_stream(stream_id)?;
        // Scan using shared WASM resources with stream-specific context
        self.scan_internal(chunk)
    }
    
    fn switch_to_stream(&mut self, stream_id: Uuid) -> Result<(), ScanError> {
        if self.active_stream == Some(stream_id) {
            return Ok(());
        }
        
        // Save current stream context
        if let Some(current_id) = self.active_stream {
            self.save_context(current_id)?;
        }
        
        // Load or create new context
        self.load_context(stream_id)?;
        self.active_stream = Some(stream_id);
        Ok(())
    }
}
```

### Pros
- **Resource efficiency**: Single WASM instance shared across streams
- **Fast context switching**: Only copy necessary state
- **Good memory/performance balance**: Scales well with stream count
- **Concurrent capability**: Can be extended for parallel scanning
- **Moderate implementation complexity**: Builds on existing code

### Cons
- **State management complexity**: Must carefully manage context switches
- **Shared resource coordination**: Need to ensure proper isolation
- **More complex than Approach 1**: Requires understanding of scanner internals
- **Potential for state leakage**: Must ensure complete context separation

### Memory Estimate
WASM_RESOURCES + (N × CONTEXT_SIZE), where CONTEXT_SIZE << SCANNER_SIZE

## Approach 4: Stream Pool with LRU Eviction

### Concept
Maintain a pool of active scanners with automatic eviction of least recently used streams.

```rust
pub struct StreamPool<'r> {
    rules: &'r Rules,
    max_active_streams: usize,
    active_scanners: LruCache<Uuid, StreamingScanner<'r>>,
    archived_states: HashMap<Uuid, ArchivedState>,
    archive_backend: Box<dyn ArchiveBackend>, // Memory, disk, S3, etc.
}

impl<'r> StreamPool<'r> {
    pub fn scan_chunk(&mut self, stream_id: Uuid, chunk: &[u8]) -> Result<(), ScanError> {
        let scanner = if let Some(scanner) = self.active_scanners.get_mut(&stream_id) {
            scanner
        } else {
            self.restore_or_create_scanner(stream_id)?
        };
        scanner.scan_chunk(chunk)
    }
    
    fn restore_or_create_scanner(&mut self, stream_id: Uuid) -> Result<&mut StreamingScanner<'r>, ScanError> {
        // Check if we need to evict
        if self.active_scanners.len() >= self.max_active_streams {
            self.evict_lru_scanner()?;
        }
        
        // Restore from archive or create new
        let scanner = if let Some(state) = self.archived_states.remove(&stream_id) {
            StreamingScanner::restore(self.rules, state)?
        } else {
            StreamingScanner::new(self.rules)
        };
        
        self.active_scanners.put(stream_id, scanner);
        Ok(self.active_scanners.get_mut(&stream_id).unwrap())
    }
}
```

### Pros
- **Handles unlimited streams**: Can archive to disk/cloud
- **Configurable memory usage**: Set max active streams
- **Good for long-running services**: Automatic resource management
- **Extensible storage**: Can use different archive backends

### Cons
- **Most complex implementation**: Requires archive/restore logic
- **Performance variability**: Slow when restoring archived streams
- **Additional dependencies**: LRU cache, serialization
- **Overkill for small stream counts**: Unnecessary complexity

### Use Cases
Best for applications with:
- Hundreds or thousands of streams
- Long-lived streams with idle periods
- Need for persistence across restarts

## Recommendation: Approach 3

I recommend **Approach 3 (Modified StreamingScanner with Stream Context)** for the following reasons:

### 1. Optimal Resource Usage
- Shares expensive WASM resources (store, instance, compiled code)
- Per-stream overhead is just the context state
- Memory usage: O(1) for WASM + O(N) for contexts

### 2. Performance Characteristics
- Fast context switching (microseconds)
- No serialization overhead
- Maintains scanner performance for each stream

### 3. Implementation Feasibility
- Builds on existing StreamingScanner code
- Clear separation between shared and stream-specific state
- Easier to debug than serialization approach

### 4. Scalability
- Can handle 100s of concurrent streams efficiently
- Linear memory growth with predictable overhead
- Can be extended with pooling if needed later

### 5. Future Extensibility
- Can add concurrent scanning with multiple WASM instances
- Easy to add persistence by serializing contexts
- Can implement priority-based scheduling

## Implementation Guidelines for Approach 3

### State Division
**Shared Resources** (one instance):
- WASM store and instance
- Compiled rules
- Global variables (filesize, pattern_search_done)
- Timeout configuration

**Per-Stream Context**:
- Pattern matches
- Matching rules (private and non-private)
- Byte and line counters
- Global offset
- Module outputs
- Temporary match state

### Key Implementation Points
1. **Context Switching**: Must save/restore all mutable state
2. **WASM Memory Management**: Clear bitmaps between streams
3. **Module State**: Handle module outputs per stream
4. **Thread Safety**: Use Arc<Mutex<>> if concurrent access needed
5. **Error Handling**: Ensure cleanup on scan errors

### API Design
```rust
pub trait MultiStreamScanner {
    fn scan_chunk(&mut self, stream_id: Uuid, chunk: &[u8]) -> Result<(), ScanError>;
    fn scan_line(&mut self, stream_id: Uuid, line: &[u8]) -> Result<(), ScanError>;
    fn get_matches(&self, stream_id: &Uuid) -> Option<StreamResults>;
    fn close_stream(&mut self, stream_id: &Uuid) -> Option<StreamResults>;
    fn active_streams(&self) -> Vec<Uuid>;
    fn reset_stream(&mut self, stream_id: &Uuid) -> Result<(), ScanError>;
}
```

## Conclusion

While each approach has its merits, Approach 3 provides the best balance of:
- Memory efficiency
- Performance
- Implementation complexity
- Future extensibility

It's suitable for applications needing to handle dozens to hundreds of concurrent streams without the overhead of full scanner duplication or serialization costs.