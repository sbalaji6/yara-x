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