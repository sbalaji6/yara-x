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