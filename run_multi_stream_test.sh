#!/bin/bash

echo "=== Setting up test files ==="

# Create YARA rules file
cat > test_multi_stream.yar << 'EOF'
rule test_pattern1 {
    strings:
        $a = "ERROR"
        $b = "WARNING"
    condition:
        $a or $b
}

rule test_pattern2 {
    strings:
        $log = /\d{4}-\d{2}-\d{2}/
    condition:
        $log
}

rule test_pattern3 {
    strings:
        $user = "user_id"
        $session = "session"
    condition:
        $user and $session
}
EOF

# Create first log file
cat > test_input1.log << 'EOF'
2024-01-01 10:00:00 INFO Starting application
2024-01-01 10:00:01 ERROR Failed to connect to database
2024-01-01 10:00:02 WARNING Connection timeout
2024-01-01 10:00:03 INFO Retrying connection
2024-01-01 10:00:04 ERROR Authentication failed for user_id=12345
2024-01-01 10:00:05 INFO Created new session=abc123
2024-01-01 10:00:06 DEBUG Processing request
2024-01-01 10:00:07 ERROR Invalid user_id in session
2024-01-01 10:00:08 WARNING Memory usage high
2024-01-01 10:00:09 INFO Request completed
EOF

# Create second log file
cat > test_input2.log << 'EOF'
2024-01-02 09:00:00 INFO Server started
2024-01-02 09:00:01 DEBUG Loading configuration
2024-01-02 09:00:02 INFO Configuration loaded
2024-01-02 09:00:03 WARNING Old config detected
2024-01-02 09:00:04 INFO Starting services
2024-01-02 09:00:05 ERROR Service initialization failed
2024-01-02 09:00:06 INFO Fallback mode activated
2024-01-02 09:00:07 DEBUG Checking user_id permissions
2024-01-02 09:00:08 INFO Session established for user
2024-01-02 09:00:09 ERROR Critical error in session handler
EOF

echo "=== Building the binary ==="
cargo build --bin multi-input-stream-perf

echo -e "\n=== Running test with 2 files, chunk size 3 ==="
./target/debug/multi-input-stream-perf -r test_multi_stream.yar -i test_input1.log test_input2.log -c 3

echo -e "\n=== Creating more test files for larger test ==="
for i in {3..7}; do 
    cp test_input1.log test_input$i.log
done

echo -e "\n=== Running test with 7 files, chunk size 2 ==="
./target/debug/multi-input-stream-perf -r test_multi_stream.yar -i test_input*.log -c 2