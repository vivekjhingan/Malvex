rule SuspiciousAPIs {
    strings:
        $a1 = "CreateRemoteThread" nocase
        $a2 = "VirtualAlloc" nocase
        $a3 = "WriteProcessMemory" nocase
    condition:
        any of them
}

rule SuspiciousStrings {
    strings:
        $s1 = "powershell -enc" nocase
        $s2 = "cmd.exe /c" nocase
        $s3 = "CurrentVersion\\Run" nocase
    condition:
        any of them
}

rule SuspiciousURLs {
    strings:
        $url = /https?:\/\/[\w.-]+/ nocase
    condition:
        $url
}