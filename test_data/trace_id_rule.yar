rule trace_id_pattern {
    strings:
        $trace = /traceId:/
    condition:
        $trace
}