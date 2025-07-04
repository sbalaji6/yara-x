rule simple_test {
    strings:
        $a = "test"
    condition:
        $a
}