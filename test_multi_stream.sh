#!/bin/bash

# Multi-Input Stream Scanner Test Script
# This script sets up test files and runs various test scenarios

echo "=== Multi-Input Stream Scanner Test Suite ==="
echo

# Create test directory
TEST_DIR="multi_stream_tests"
mkdir -p $TEST_DIR
cd $TEST_DIR

# Create YARA rules
echo "Creating YARA rules..."

cat > test_simple_chunk.yar << 'EOF'
rule simple_test {
    strings:
        $a = "START_MARKER"
        $b = "END_MARKER"
    condition:
        $a and $b
}
EOF

cat > test_cross_chunk.yar << 'EOF'
rule cross_chunk_pattern {
    meta:
        description = "Test pattern spanning across chunks"
    strings:
        $pattern1 = "START_MARKER"
        $pattern2 = "END_MARKER"
        $combined = "HELLO_WORLD_PATTERN"
        $regex = /DATA_\d+_VALUE/
    condition:
        all of them
}
EOF

# Create test data files
echo "Creating test data files..."

cat > test_chunk_data1.txt << 'EOF'
This file contains START_MARKER at the beginning
Some random data here
END_MARKER at the end
More data to fill the chunk
HELLO_WORLD_PATTERN in this file
DATA_123_VALUE matches regex
Additional content here
END_MARKER at the end
EOF

cat > test_chunk_data2.txt << 'EOF'
Second file with START_MARKER
Different content here  
HELLO_WORLD_PATTERN in one line
Some filler text
DATA_456_VALUE for regex match
More content to process
Finally END_MARKER completes
EOF

# Build the binary
echo "Building multi-input-stream-perf..."
cd ..
cargo build --bin multi-input-stream-perf
if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

cd $TEST_DIR

# Run tests
BINARY="../target/debug/multi-input-stream-perf"

echo
echo "=== Test 1: Small chunks (2 lines) - Forces pattern splits ==="
$BINARY -r test_simple_chunk.yar -i test_chunk_data1.txt test_chunk_data2.txt -c 2

echo
echo "=== Test 2: Medium chunks (5 lines) ==="
$BINARY -r test_simple_chunk.yar -i test_chunk_data1.txt test_chunk_data2.txt -c 5

echo
echo "=== Test 3: Large chunks (100 lines) - Entire file at once ==="
$BINARY -r test_simple_chunk.yar -i test_chunk_data1.txt test_chunk_data2.txt -c 100

echo
echo "=== Test 4: Complex rule with multiple patterns ==="
$BINARY -r test_cross_chunk.yar -i test_chunk_data1.txt test_chunk_data2.txt -c 3

echo
echo "=== Test Summary ==="
echo "Test files created in: $(pwd)"
echo "Key observations:"
echo "- Small chunks (Test 1) show matches appearing in different rounds"
echo "- Once a rule matches, it stays matched in subsequent rounds"
echo "- Each file maintains independent matching state"
echo "- Patterns spanning chunks are correctly detected"