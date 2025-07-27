# YARA-X Streaming Architecture and Modifications

## Table of Contents
1. [Overview](#overview)
2. [Original YARA-X Architecture](#original-yara-x-architecture)
3. [Streaming Modifications](#streaming-modifications)
4. [Implementation Details](#implementation-details)
5. [Memory Optimization](#memory-optimization)
6. [Usage Examples](#usage-examples)

## Overview

This document provides a comprehensive overview of YARA-X's architecture and the streaming modifications implemented in this repository to support multi-stream pattern matching with deduplication capabilities.

## Original YARA-X Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────┐
│                    YARA Rules                           │
│                  (Source Code)                          │
└───────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                    Compiler                             │
│  • Parse rules                                          │
│  • Generate WASM code                                   │
│  • Build pattern automata                               │
└───────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                  Compiled Rules                         │
│  • WASM module                                          │
│  • Aho-Corasick automaton                              │
│  • Regex patterns                                       │
└───────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                    Scanner                              │
│  • Pattern matching engine                              │
│  • WASM runtime (wasmtime)                              │
│  • Rule evaluation                                      │
└─────────────────────────────────────────────────────────┘
```

### Memory Layout

The WASM module memory is organized as follows:

```
┌──────────────────────────┐ 0x0000
│ Variable undefined flags │ (128 bits)
├──────────────────────────┤ 0x0010 (VARS_STACK_START)
│ Variable storage         │
│ • Variable #0            │
│ • Variable #1            │
│ • ...                    │
├──────────────────────────┤ 0x0400 (LOOKUP_INDEXES_START)
│ Field lookup indexes     │
├──────────────────────────┤ 0x0800 (MATCHING_RULES_BITMAP_BASE)
│ Matching rules bitmap    │ (1 bit per rule)
│                          │
├──────────────────────────┤
│ Matching patterns bitmap │ (1 bit per pattern)
│                          │
└──────────────────────────┘
```

### Pattern Matching Flow

1. **Pattern Detection Phase:**
   ```rust
   // Aho-Corasick automaton scans input data
   for pattern_match in aho_corasick.find_iter(data) {
       // Store match: {pattern_id, range: start..end}
       pattern_matches.add(pattern_id, Match {
           range: match_start..match_end,
           xor_key: None,
       });
       // Set bit in pattern bitmap
       set_pattern_bit(pattern_id);
   }
   ```

2. **Rule Evaluation Phase:**
   ```rust
   // WASM code evaluates rule conditions
   // Checks pattern bitmap to see which patterns matched
   if pattern_matched(pattern_id) && condition_met() {
       // Set bit in rule bitmap
       set_rule_bit(rule_id);
       // Callback to Rust
       rule_match_callback(rule_id);
   }
   ```

### Bitmap Management

- **Pattern Bitmap**: Each bit represents whether a specific pattern has been found
- **Rule Bitmap**: Each bit represents whether a specific rule has matched
- Bitmaps enable fast lookups during rule evaluation in WASM

## Streaming Modifications

### Multi-Stream Architecture

```
┌─────────────────────────────────────────────────────────┐
│                MultiStreamScanner                       │
│                                                         │
│  ┌─────────────────┐  ┌─────────────────┐             │
│  │ Stream Context  │  │ Stream Context  │  ...         │
│  │ UUID: abc-123   │  │ UUID: def-456   │             │
│  │ ┌─────────────┐ │  │ ┌─────────────┐ │             │
│  │ │Pattern Match│ │  │ │Pattern Match│ │             │
│  │ │   Storage   │ │  │ │   Storage   │ │             │
│  │ └─────────────┘ │  │ └─────────────┘ │             │
│  │ ┌─────────────┐ │  │ ┌─────────────┐ │             │
│  │ │Trace ID Set│ │  │ │Trace ID Set│ │             │
│  │ │(Dedup)     │ │  │ │(Dedup)     │ │             │
│  │ └─────────────┘ │  │ └─────────────┘ │             │
│  │ ┌─────────────┐ │  │ ┌─────────────┐ │             │
│  │ │  Bitmaps   │ │  │ │  Bitmaps   │ │             │
│  │ └─────────────┘ │  │ └─────────────┘ │             │
│  └─────────────────┘  └─────────────────┘             │
│                                                         │
│  ┌─────────────────────────────────────────┐           │
│  │           WASM Store                     │           │
│  │  • Shared WASM module                    │           │
│  │  • Rule evaluation engine                │           │
│  └─────────────────────────────────────────┘           │
│                                                         │
│  ┌─────────────────────────────────────────┐           │
│  │         Offset Cache (LevelDB)           │           │
│  │  • Store line data by trace ID           │           │
│  │  • LRU cache for fast access             │           │
│  └─────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────┘
```

### Key Modifications

#### 1. Enhanced Match Structure

```rust
// Original Match struct
pub struct Match {
    pub range: Range<usize>,
    pub xor_key: Option<u8>,
}

// Modified Match struct with trace ID
pub struct Match {
    pub range: Range<usize>,
    pub xor_key: Option<u8>,
    pub trace_id: Option<String>,  // NEW: Extracted trace ID
}
```

#### 2. Trace ID Extraction

```rust
fn extract_trace_id(data: &[u8], match_range: &Range<usize>) -> Option<String> {
    // Find the line containing the match
    let line_start = data[..match_range.start]
        .iter()
        .rposition(|&b| b == b'\n')
        .map(|pos| pos + 1)
        .unwrap_or(0);
    
    let line_end = data[match_range.end..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|pos| match_range.end + pos)
        .unwrap_or(data.len());
    
    let line = &data[line_start..line_end];
    
    // Extract last quoted string as trace ID
    // Example: 'ERROR (trace_id="ABC123")' → "ABC123"
    extract_last_quoted_string(line)
}
```

#### 3. Pattern Deduplication

```rust
struct StreamContext {
    // Original fields
    pattern_matches: PatternMatches,
    rule_bitmap: Vec<u8>,
    pattern_bitmap: Vec<u8>,
    
    // NEW: Track unique trace IDs per pattern
    pattern_trace_ids: HashMap<PatternId, HashSet<String>>,
}

// Deduplication during pattern matching
fn add_pattern_match(
    &mut self,
    pattern_id: PatternId,
    match_: Match,
) -> bool {
    if let Some(trace_id) = &match_.trace_id {
        let trace_ids = self.pattern_trace_ids
            .entry(pattern_id)
            .or_insert_with(HashSet::new);
        
        if !trace_ids.insert(trace_id.clone()) {
            // Duplicate trace ID - skip this match
            return false;
        }
    }
    
    // Add unique match
    self.pattern_matches.add(pattern_id, match_);
    true
}
```

#### 4. Offset Cache Implementation

```rust
pub struct OffsetCache {
    db: RefCell<LevelDB>,
    lru_cache: Arc<Mutex<LruCache<String, Vec<u8>>>>,
    db_path: String,
}

impl OffsetCache {
    pub fn new(db_path: &str) -> Result<Self, String> {
        let opts = Options {
            create_if_missing: true,
            write_buffer_size: 128 * 1024 * 1024,     // 128MB
            block_cache_capacity: 256 * 1024 * 1024,  // 256MB
            block_size: 16 * 1024,                    // 16KB
        };
        
        let db = LevelDB::open(db_path, opts)?;
        let lru = LruCache::new(NonZeroUsize::new(1000).unwrap());
        
        Ok(Self {
            db: RefCell::new(db),
            lru_cache: Arc::new(Mutex::new(lru)),
            db_path: db_path.to_string(),
        })
    }
    
    pub fn put(&self, trace_id: &str, data: &[u8]) -> Result<(), String> {
        // Store in LevelDB
        self.db.borrow_mut().put(trace_id.as_bytes(), data)?;
        
        // Update LRU cache
        if let Ok(mut cache) = self.lru_cache.lock() {
            cache.put(trace_id.to_string(), data.to_vec());
        }
        
        Ok(())
    }
    
    pub fn get(&self, trace_id: &str) -> Option<Vec<u8>> {
        // Check LRU cache first
        if let Ok(mut cache) = self.lru_cache.lock() {
            if let Some(data) = cache.get(trace_id) {
                return Some(data.clone());
            }
        }
        
        // Fall back to LevelDB
        self.db.borrow_mut().get(trace_id.as_bytes())
    }
}
```

### Pattern Matching Flow with Streaming

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Chunk #1      │     │   Chunk #2      │     │   Chunk #3      │
│                 │     │                 │     │                 │
│ "ERROR trace_   │ --> │ id='ABC123'"    │ --> │ "INFO done"     │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Pattern Matching Engine                      │
│                                                                  │
│  1. Scan chunk with Aho-Corasick                               │
│  2. Extract trace IDs from matched lines                        │
│  3. Check deduplication (pattern_trace_ids)                     │
│  4. Store unique matches                                         │
│  5. Cache line data in offset cache                            │
└─────────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Rule Evaluation                             │
│                                                                  │
│  • WASM evaluates conditions                                    │
│  • Only considers new unique matches                            │
│  • Triggers callback with trace IDs                             │
└─────────────────────────────────────────────────────────────────┘
```

## Implementation Details

### Multi-Stream Scanner API

```rust
// Create scanner
let mut scanner = MultiStreamScanner::new(&rules);

// Enable offset cache
scanner.enable_offset_cache("/tmp/yara_cache")?;

// Set callback for rule matches
scanner.set_rule_match_callback(|namespace, stream_id, rule, trace_ids| {
    println!("Rule {} matched in stream {} with trace IDs: {:?}", 
             rule, stream_id, trace_ids);
});

// Process chunks from multiple streams
let stream1 = Uuid::new_v4();
let stream2 = Uuid::new_v4();

scanner.scan_chunk(&stream1, chunk1_data)?;
scanner.scan_chunk(&stream2, chunk2_data)?;
scanner.scan_chunk(&stream1, chunk1_data_continued)?;

// Get results
if let Some(results) = scanner.get_matches(&stream1) {
    for rule in results.matching_rules() {
        println!("Stream 1 matched: {}", rule.identifier());
    }
}
```

### Stream Context Lifecycle

1. **Creation**: When first chunk for a UUID is scanned
2. **State Preservation**: After each chunk, state is saved
3. **State Restoration**: Before scanning next chunk
4. **Cleanup**: Can be manually cleared or auto-evicted

### Callback System

```rust
pub type RuleMatchCallback = Box<dyn FnMut(
    &str,        // namespace
    &Uuid,       // stream_id
    &str,        // rule_identifier
    &[String]    // trace_ids
)>;

// Callback is invoked when:
// 1. Rule matches for the first time in a stream
// 2. Rule matches with new trace IDs
```

## Memory Optimization

### Virtual Memory vs RSS

- **Virtual Memory (VSZ)**: ~850MB
  - WASM runtime reservations
  - Memory-mapped regions
  - Guard pages
  
- **Resident Set Size (RSS)**: ~250-350MB
  - Compiled WASM code
  - Pattern automata
  - Active stream contexts
  - LevelDB cache

### Optimization Strategies

1. **Lazy JIT Compilation**: Compile WASM code on-demand
2. **Stream Context Pooling**: Reuse contexts instead of allocating new
3. **Reduced Parallel Streams**: Process fewer streams concurrently
4. **Smaller Buffer Sizes**: Use smaller read buffers
5. **Build Optimizations**: 
   ```bash
   RUSTFLAGS="-C opt-level=z" cargo build --release
   ```

### Memory Configuration

```rust
// LevelDB configuration for offset cache
let opts = Options {
    write_buffer_size: 128 * 1024 * 1024,    // 128MB write buffer
    block_cache_capacity: 256 * 1024 * 1024, // 256MB block cache
    block_size: 16 * 1024,                   // 16KB blocks
};

// WASM configuration
config.memory_reservation(0x1000000);        // 16MB per module
config.memory_reservation_for_growth(0);     // No growth reservation
```

## Usage Examples

### Basic Multi-Stream Scanning

```rust
use yara_x::{Compiler, MultiStreamScanner};
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile rules
    let mut compiler = Compiler::new();
    compiler.add_source(r#"
        rule log_errors {
            strings:
                $error = /ERROR.*trace_id/
            condition:
                $error
        }
    "#)?;
    let rules = compiler.build();
    
    // Create scanner
    let mut scanner = MultiStreamScanner::new(&rules);
    
    // Process multiple log streams
    let stream1 = Uuid::new_v4();
    let stream2 = Uuid::new_v4();
    
    scanner.scan_chunk(&stream1, b"ERROR: Failed (trace_id=\"ABC123\")\n")?;
    scanner.scan_chunk(&stream2, b"ERROR: Failed (trace_id=\"XYZ789\")\n")?;
    scanner.scan_chunk(&stream1, b"ERROR: Retry (trace_id=\"ABC123\")\n")?; // Duplicate
    
    Ok(())
}
```

### With Offset Cache

```rust
// Enable offset cache for cross-chunk data access
scanner.enable_offset_cache("/tmp/yara_cache")?;

// Now the scanner stores line data by trace ID
// Useful for rules that need to access data at specific offsets
```

### Performance Testing

```rust
// The multi-input-stream-perf binary demonstrates:
// - Parallel file processing
// - Chunk-based streaming
// - Memory usage monitoring
// - Deduplication effectiveness

cargo build --release --bin multi-input-stream-perf
./target/release/multi-input-stream-perf \
    -r rules.yar \
    -d /var/log \
    -p 10 \
    -c 65536
```

## Conclusion

The streaming modifications to YARA-X enable:

1. **Multi-stream processing**: Handle multiple concurrent data streams
2. **Pattern deduplication**: Track unique matches via trace IDs
3. **Cross-chunk data access**: Store and retrieve data by trace ID
4. **Memory efficiency**: Process large files without loading entirely
5. **Real-time monitoring**: Suitable for continuous log analysis

These enhancements make YARA-X suitable for streaming applications like log monitoring, real-time threat detection, and large-scale data processing while maintaining the core pattern matching capabilities of the original engine.