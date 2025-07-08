# Multi-Input Stream UUID Parsing Fix Documentation

## Issue Description

The `multi-input-stream-perf` tool was documented to support passing UUIDs with input files in the format `filename:uuid`, but the implementation was missing this feature. The tool would fail when trying to use this syntax.

## Date
2025-07-08

## Problem Analysis

### Original Implementation
The original code accepted input files as `Vec<PathBuf>`, which meant:
- Only file paths were accepted
- UUIDs were always auto-generated
- The documented syntax `file.txt:uuid` would cause an error because the entire string would be treated as a file path

### Code Before Fix
```rust
// In Args struct
#[arg(short = 'i', long = "input", required = true, num_args = 1..)]
input_files: Vec<PathBuf>,

// In main function
for (i, path) in args.input_files.iter().enumerate() {
    let file = File::open(path)?;  // Would fail for "file.txt:uuid"
    readers.push(BufReader::new(file));
    uuids.push(Uuid::new_v4());  // Always generated new UUID
    active_files.push(i);
}
```

## Solution Implementation

### Changes Made

1. **Changed input type from `Vec<PathBuf>` to `Vec<String>`**
   - Allows parsing of the input string before treating it as a path
   - Location: `cli/src/multi_input_stream_perf.rs:17`

2. **Added UUID parsing logic**
   - Splits input by the last colon (`:`)
   - Validates if the part after colon is a valid UUID
   - Falls back to treating entire string as path if not valid UUID
   - Location: `cli/src/multi_input_stream_perf.rs:56-80`

3. **Added separate storage for parsed file paths**
   - Created `file_paths` vector to store parsed `PathBuf` values
   - Updated all references from `args.input_files` to `file_paths`

### Detailed Code Changes

```rust
// 1. Changed argument type
#[arg(short = 'i', long = "input", required = true, num_args = 1..)]
input_files: Vec<String>,  // Changed from Vec<PathBuf>

// 2. Added parsing logic
let mut file_paths = Vec::new();

for (i, input) in args.input_files.iter().enumerate() {
    let (path, uuid) = if let Some(colon_pos) = input.rfind(':') {
        // Check if what follows the colon looks like a UUID
        let potential_uuid = &input[colon_pos + 1..];
        if let Ok(parsed_uuid) = Uuid::parse_str(potential_uuid) {
            // Valid UUID found
            let path = PathBuf::from(&input[..colon_pos]);
            (path, parsed_uuid)
        } else {
            // Not a valid UUID, treat the whole thing as a path
            (PathBuf::from(input), Uuid::new_v4())
        }
    } else {
        // No colon found, treat as path and generate UUID
        (PathBuf::from(input), Uuid::new_v4())
    };
    
    println!("Processing file: {} with UUID: {}", path.display(), uuid);
    
    let file = File::open(&path)?;
    readers.push(BufReader::new(file));
    uuids.push(uuid);
    file_paths.push(path);
    active_files.push(i);
}
```

### Key Features of the Fix

1. **Uses `rfind(':')` to find the last colon**
   - Handles paths with colons correctly (e.g., `C:\folder\file.txt` on Windows)
   - Only the last colon is considered as a potential UUID separator

2. **Validates UUID format**
   - Uses `Uuid::parse_str()` to check if the string after colon is a valid UUID
   - If parsing fails, treats the entire input as a file path

3. **Backwards compatible**
   - Files without `:uuid` suffix work as before
   - Auto-generates UUIDs when not provided

## Testing Instructions

### Prerequisites

1. Build the fixed binary:
```bash
cargo build --bin multi-input-stream-perf
```

2. Create test files:
```bash
# Create test data files
echo "This is test file 1 with some content" > /tmp/test1.txt
echo "This is test file 2 with more content" > /tmp/test2.txt
echo "File with colon in name" > "/tmp/test:file.txt"

# Create a simple YARA rule
echo 'rule test_rule {
    strings:
        $test = "test"
        $file = "file"
    condition:
        any of them
}' > /tmp/test.yar
```

### Test Cases

#### Test 1: File with explicit UUID
```bash
./target/debug/multi-input-stream-perf \
    -r /tmp/test.yar \
    -i /tmp/test1.txt:550e8400-e29b-41d4-a716-446655440000 \
    -c 10
```

**Expected Output:**
- Should show: `Processing file: /tmp/test1.txt with UUID: 550e8400-e29b-41d4-a716-446655440000`
- The specified UUID should be used throughout processing

#### Test 2: File without UUID (auto-generate)
```bash
./target/debug/multi-input-stream-perf \
    -r /tmp/test.yar \
    -i /tmp/test2.txt \
    -c 10
```

**Expected Output:**
- Should show: `Processing file: /tmp/test2.txt with UUID: [auto-generated-uuid]`
- A new UUID should be generated automatically

#### Test 3: Multiple files with mixed UUID specification
```bash
./target/debug/multi-input-stream-perf \
    -r /tmp/test.yar \
    -i /tmp/test1.txt:123e4567-e89b-12d3-a456-426614174000 \
    -i /tmp/test2.txt \
    -i /tmp/test1.txt:987f6543-e21b-12d3-a456-426614174000 \
    -c 5
```

**Expected Output:**
- First instance of test1.txt uses UUID: `123e4567-e89b-12d3-a456-426614174000`
- test2.txt gets an auto-generated UUID
- Second instance of test1.txt uses UUID: `987f6543-e21b-12d3-a456-426614174000`

#### Test 4: File with colon in name (no UUID)
```bash
./target/debug/multi-input-stream-perf \
    -r /tmp/test.yar \
    -i "/tmp/test:file.txt" \
    -c 10
```

**Expected Output:**
- Should show: `Processing file: /tmp/test:file.txt with UUID: [auto-generated-uuid]`
- The colon in the filename should be preserved

#### Test 5: Invalid UUID format
```bash
./target/debug/multi-input-stream-perf \
    -r /tmp/test.yar \
    -i /tmp/test1.txt:not-a-valid-uuid \
    -c 10
```

**Expected Output:**
- Should show: `Processing file: /tmp/test1.txt:not-a-valid-uuid with UUID: [auto-generated-uuid]`
- The entire string is treated as a filename since "not-a-valid-uuid" is not valid

### Full Integration Test

```bash
# Create a comprehensive test
cat > /tmp/integration_test.sh << 'EOF'
#!/bin/bash

# Create test files
echo "Server log entry 1" > /tmp/server1.log
echo "Server log entry 2" > /tmp/server2.log
echo "Server log entry 3" > /tmp/server3.log

# Create YARA rule
echo 'rule server_logs {
    strings:
        $log = "log"
        $server = "Server"
    condition:
        all of them
}' > /tmp/server.yar

# Run with mixed UUID specifications
./target/debug/multi-input-stream-perf \
    -r /tmp/server.yar \
    -i /tmp/server1.log:11111111-2222-3333-4444-555555555555 \
    -i /tmp/server2.log \
    -i /tmp/server3.log:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee \
    -c 1

# Clean up
rm -f /tmp/server*.log /tmp/server.yar
EOF

chmod +x /tmp/integration_test.sh
/tmp/integration_test.sh
```

## Verification Checklist

✅ **Binary builds successfully** - No compilation errors after changes
✅ **Explicit UUID parsing** - Files with `:uuid` syntax use the provided UUID
✅ **Auto-generation works** - Files without UUID get auto-generated UUIDs
✅ **Colon in filename handling** - Files with colons in names work correctly
✅ **Invalid UUID handling** - Invalid UUIDs cause fallback to filename interpretation
✅ **Multiple files processing** - Can process multiple files with different UUID specifications
✅ **Output shows UUIDs** - Final summary displays UUIDs for verification

## Impact

- **No breaking changes** - Existing usage without UUIDs continues to work
- **New functionality** - Enables UUID specification as documented
- **Better debugging** - Shows which UUID is assigned to each file
- **Use case support** - Allows resuming processing with same UUIDs

## Related Files

- **Source file**: `cli/src/multi_input_stream_perf.rs`
- **Documentation**: `MULTI_INPUT_STREAM_PERF_TEST.md`
- **Build configuration**: `cli/Cargo.toml`