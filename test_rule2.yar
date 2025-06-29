rule another_test {
    strings:
        $d = "normal"
        $e = "line"
    condition:
        #d >= 3 and #e >= 5
}