rule test_pattern {
    strings:
        $a = "malicious"
        $b = "suspicious"
        $c = "pattern"
    condition:
        any of them
}

rule test_combined {
    strings:
        $x = "malicious"
        $y = "pattern"
    condition:
        all of them
}