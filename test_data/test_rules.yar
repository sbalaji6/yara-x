rule malware_signature
{
    strings:
        $malware = "malware_signature_123"
        $evil = "evil_function_call"
        $suspicious = "suspicious_behavior_detected"
    
    condition:
        any of them
}

rule network_indicators
{
    strings:
        $ip = /192\.168\.\d{1,3}\.\d{1,3}/
        $suspicious_url = "suspicious-site.com"
        $malicious_url = "malicious-domain.net"
        $backdoor = "backdoor connection"
        $port = "port 4444"
    
    condition:
        2 of them
}

rule mixed_patterns
{
    strings:
        $pattern1 = "malware_signature_123"
        $pattern2 = /192\.168\.\d{1,3}\.\d{1,3}/
        $pattern3 = "Mixed patterns"
    
    condition:
        all of them
}

rule benign_content
{
    strings:
        $normal = "normal file"
        $regular = "regular text"
        $nothing = "Nothing suspicious"
    
    condition:
        2 of them
}