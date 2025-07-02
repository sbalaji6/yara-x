rule test_standard_regex {
    strings:
        // Standard regex patterns that work without relaxed mode
        $a = /test.*pattern/
        $b = /foo\{2\}bar/
        $c = /data.+file/
        
    condition:
        any of them
}