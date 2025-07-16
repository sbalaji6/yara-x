# YARA-X Multi-Stream Streaming Detection Engine Architecture

## Overview

The YARA-X multi-stream streaming detection engine enables concurrent scanning of multiple independent data streams while sharing WASM resources efficiently. Each stream maintains its own state and can be processed incrementally, making it ideal for scenarios like log analysis where multiple sources need to be scanned simultaneously.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          MultiStreamScanner                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────┐         ┌────────────────────────────────┐   │
│  │   Stream Manager    │         │      WASM Engine               │   │
│  ├─────────────────────┤         ├────────────────────────────────┤   │
│  │ • Stream Contexts   │         │ • Compiled Rules               │   │
│  │   HashMap<UUID,     │         │ • Pattern Matching Logic       │   │
│  │   StreamContext>    │◄────────┤ • Rule Evaluation              │   │
│  │ • Active Stream ID  │         │ • Module Functions             │   │
│  │ • Stream Switching  │         │ • Main Memory                  │   │
│  └─────────────────────┘         └────────────────────────────────┘   │
│            │                                  │                         │
│            ▼                                  ▼                         │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                        StreamContext                             │  │
│  ├─────────────────────────────────────────────────────────────────┤  │
│  │ ┌──────────────────┐  ┌──────────────────┐  ┌────────────────┐ │  │
│  │ │ Pattern Matches  │  │   Rule States    │  │    Bitmaps     │ │  │
│  │ ├──────────────────┤  ├──────────────────┤  ├────────────────┤ │  │
│  │ │ • PatternId →    │  │ • Matching Rules │  │ • Rule Bitmap  │ │  │
│  │ │   MatchList      │  │ • Private Rules  │  │ • Pattern      │ │  │
│  │ │ • Match Range    │  │ • Non-Private    │  │   Bitmap       │ │  │
│  │ │ • XOR Key        │  │   Rules          │  │ • Stored in    │ │  │
│  │ │ • Trace ID       │  │ • Unconfirmed    │  │   WASM Memory  │ │  │
│  │ └──────────────────┘  │   Matches        │  └────────────────┘ │  │
│  │                       └──────────────────┘                      │  │
│  │                                                                 │  │
│  │ ┌──────────────────┐  ┌──────────────────┐  ┌────────────────┐ │  │
│  │ │  Stream Stats    │  │ Module Outputs   │  │ Offset Tracking│ │  │
│  │ ├──────────────────┤  ├──────────────────┤  ├────────────────┤ │  │
│  │ │ • Bytes Processed│  │ • Protobuf Msgs  │  │ • Global Offset│ │  │
│  │ │ • Line Count     │  │ • Per Module     │  │ • For Streaming│ │  │
│  │ │ • Total Matches  │  │                  │  │   Adjustment   │ │  │
│  │ └──────────────────┘  └──────────────────┘  └────────────────┘ │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                    Callback System                               │  │
│  ├─────────────────────────────────────────────────────────────────┤  │
│  │ • RuleMatchCallback: (namespace, stream_id, rule, trace_ids[])  │  │
│  │ • Invoked after each scan for matching rules                    │  │
│  │ • Trace IDs extracted from matched lines                        │  │
│  └─────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

## Key Components

### 1. MultiStreamScanner
The main orchestrator that manages multiple concurrent streams:
- **Stream Management**: Uses a HashMap to store StreamContext for each UUID-identified stream
- **WASM Store**: Single shared WASM instance for all streams (performance optimization)
- **Context Switching**: Saves/restores state when switching between streams
- **Callback System**: Optional callback for real-time match notifications with trace IDs

### 2. StreamContext
Per-stream state container that preserves scanning context:
- **Pattern Matches**: HashMap of PatternId → MatchList containing all matches
- **Rule States**: Tracks which rules have matched (private and non-private)
- **Bitmaps**: Rule and pattern bitmaps for WASM state preservation
- **Statistics**: Bytes processed, lines counted, global offset tracking

### 3. Bitmap System
Efficient state representation in WASM memory:
- **Rule Bitmap**: Bit array tracking which rules have matched
- **Pattern Bitmap**: Bit array tracking which patterns have matched
- **Memory Layout**: Stored at fixed offsets in WASM memory (MATCHING_RULES_BITMAP_BASE)
- **Size**: Dynamically sized based on number of rules/patterns (div_ceil(count, 8) bytes)

### 4. Match Data Structure
```rust
struct Match {
    range: Range<usize>,      // Start and end offset in data
    xor_key: Option<u8>,      // XOR key for XOR patterns
    trace_id: Option<String>, // Extracted trace ID from matched line
}
```

### 5. Trace ID Extraction
The `extract_trace_id` function extracts the last quoted string from matched lines:
1. Finds the full line containing the match
2. Scans for all double-quoted strings
3. Returns the last quoted string as the trace ID
4. Handles escaped quotes properly

## Data Flow

### Stream Scanning Process
```
1. scan_chunk/scan_line called with stream UUID
   │
2. switch_to_stream(uuid)
   ├─► Save current stream state (if exists)
   │   └─► Read bitmaps from WASM
   │   └─► Store in StreamContext
   │
   └─► Restore target stream state
       ├─► Load StreamContext
       └─► Write bitmaps to WASM
   
3. Execute WASM pattern matching
   ├─► Update scanner context with data pointer
   ├─► Set global_scan_offset for streaming
   └─► Call WASM main function
   
4. Process matches
   ├─► Extract trace IDs from matched lines
   ├─► Adjust offsets for streaming
   └─► Update pattern_matches HashMap
   
5. Save updated state back to StreamContext
   ├─► Copy pattern matches
   ├─► Copy rule states
   └─► Save WASM bitmaps
   
6. Invoke callbacks (if configured)
   └─► Call with (namespace, stream_id, rule, trace_ids[])
```

### Memory Management

The system uses several strategies to manage memory efficiently:

1. **Shared WASM Instance**: Single WASM store shared across all streams
2. **Lazy Allocation**: StreamContexts created only when streams are first used
3. **Bitmap Efficiency**: Compact bit representation for rule/pattern states
4. **Capacity Management**: PatternMatches uses threshold-based memory cleanup
5. **Context Caching**: Keeps contexts in memory for fast stream switching

### Key Features

1. **Stream Isolation**: Each stream maintains completely independent state
2. **Efficient Switching**: O(1) stream lookup with bitmap copy overhead
3. **Incremental Processing**: Supports both line-by-line and chunk processing
4. **Offset Adjustment**: Automatically adjusts pattern match offsets for streaming
5. **Trace ID Support**: Extracts identifiers from matched content
6. **Real-time Callbacks**: Immediate notification of rule matches
7. **Memory Monitoring**: Built-in memory usage tracking and statistics

## Usage Example

```rust
// Create scanner with compiled rules
let mut scanner = MultiStreamScanner::new(&rules);

// Set up callback for match notifications
scanner.set_rule_match_callback(|namespace, stream_id, rule, trace_ids| {
    println!("Rule {} matched in stream {} with traces: {:?}", 
             rule, stream_id, trace_ids);
});

// Process multiple streams
let stream1 = Uuid::new_v4();
let stream2 = Uuid::new_v4();

// Scan data from different sources
scanner.scan_chunk(&stream1, b"log data with pattern1\n")?;
scanner.scan_chunk(&stream2, b"other log data\n")?;
scanner.scan_chunk(&stream1, b"more data with pattern2\n")?;

// Get results for a specific stream
let results = scanner.get_matches(&stream1).unwrap();
for rule in results.matching_rules() {
    println!("Matched rule: {}", rule.identifier());
}

// Close stream and get final statistics
let final_results = scanner.close_stream(&stream1);
```

## Performance Considerations

1. **Context Switch Overhead**: Copying bitmaps between WASM and StreamContext
2. **Memory Growth**: Linear with number of active streams and matches
3. **Pattern Match Caching**: Matches stored per-stream, not deduplicated globally
4. **WASM Execution**: Shared engine reduces compilation overhead
5. **Callback Overhead**: Synchronous callbacks can impact scanning performance

## Limitations

1. **Memory Usage**: All stream contexts kept in memory until explicitly closed
2. **No Persistence**: Stream state lost if scanner is dropped
3. **Single-threaded**: Streams processed sequentially, not in parallel
4. **Module State**: Module outputs shared across streams (not isolated)