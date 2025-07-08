#!/bin/bash

# Create test directory
mkdir -p test_data/input_files

# Generate 20 test files with different content patterns
for i in {1..20}; do
    echo "=== Creating file test_$i.txt ==="
    
    # Add some variety to the content
    case $((i % 4)) in
        0)
            # Files with malware-like patterns
            cat > "test_data/input_files/test_$i.txt" << EOF
This is test file number $i
Contains some suspicious patterns
malware_signature_123
evil_function_call()
suspicious_behavior_detected
Line 6 with more content
Line 7 with even more content
Line 8 with additional data
Line 9 with extra information
Line 10 final line
EOF
            ;;
        1)
            # Files with network patterns
            cat > "test_data/input_files/test_$i.txt" << EOF
Test file $i for network scanning
192.168.1.100
http://suspicious-site.com
https://malicious-domain.net
port 4444
backdoor connection established
Line 7 with network data
Line 8 with protocol info
Line 9 with packet data
Line 10 end of file
EOF
            ;;
        2)
            # Files with benign content
            cat > "test_data/input_files/test_$i.txt" << EOF
This is a normal file number $i
Just regular text content
Nothing suspicious here
Normal application data
Regular log entries
Line 6 standard output
Line 7 typical content
Line 8 normal operation
Line 9 standard procedure
Line 10 all clear
EOF
            ;;
        3)
            # Files with mixed patterns
            cat > "test_data/input_files/test_$i.txt" << EOF
Mixed content file $i
Some normal text here
But also contains: malware_signature_123
And network data: 192.168.1.100
Mixed patterns throughout
Line 6 hybrid content
Line 7 combination data
Line 8 merged information
Line 9 blended patterns
Line 10 conclusion
EOF
            ;;
    esac
    
    # Add more lines to make files larger
    for j in {11..50}; do
        echo "Additional line $j in file $i with random content: $(date +%s%N | md5sum | head -c 20)" >> "test_data/input_files/test_$i.txt"
    done
done

echo "Created 20 test files in test_data/input_files/"
ls -la test_data/input_files/