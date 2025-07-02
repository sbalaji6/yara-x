rule test_relaxed_regex {
    strings:
        // These patterns use relaxed regex syntax that YARA accepts but YARA-X doesn't by default
        
        // Invalid escape sequence - \R is treated as literal 'R' in YARA
        $a = /test\Rpattern/
        
        // Unescaped braces in non-repetition context
        $b = /foo{}bar/
        
        // Another invalid escape sequence
        $c = /data\Xfile/
        
    condition:
        any of them
}