rule simple_test {
    strings:
        $a = "START_MARKER"
        $b = "END_MARKER"
    condition:
        $a and $b
}