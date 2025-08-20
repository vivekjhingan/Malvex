/* malvex/yara_rules/malvex_rules.yar

  Malvex consolidated YARA ruleset
  - Keep all rules in this single file for simplicity and performance.
  - Each rule uses conservative conditions and a filesize guard.
  - meta.score gives a suggested severity for UI ranking (0–100).

  Notes:
  - You can extend with additional namespaces/sections below.
  - Keep strings simple & low count to reduce compile and match overhead.
*/

import "pe"

rule PS_EncodedCommand_Generic
{
    meta:
        author = "Malvex"
        description = "PowerShell encoded command usage (generic)"
        score = 65
        reference = "Heuristic"
    strings:
        $s1 = /-enc(odedcommand)?\b/i
        $s2 = /frombase64string/i
        $s3 = /iex\b/i  // Invoke-Expression
    condition:
        filesize < 50MB and 2 of ($s*)
}

rule Script_Obfuscation_Base64_Long
{
    meta:
        author = "Malvex"
        description = "Long base64-like constant strings (possible obfuscation)"
        score = 45
        reference = "Heuristic"
    strings:
        $b64 = /[A-Za-z0-9+\/]{120,}={0,2}/
    condition:
        filesize < 50MB and $b64
}

rule UPX_Packed_PE
{
    meta:
        author = "Malvex"
        description = "UPX-packed PE (benign or malicious; higher scrutiny)"
        score = 40
        reference = "UPX heuristic"
    condition:
        filesize < 50MB and
        pe.is_pe and for any i in (0..pe.number_of_sections - 1):
            ( pe.sections[i].name == ".UPX0" or pe.sections[i].name == "UPX0" )
}

rule Office_Macro_Keywords
{
    meta:
        author = "Malvex"
        description = "Office macro auto-run keywords"
        score = 55
        reference = "Heuristic"
    strings:
        $a1 = "AutoOpen"
        $a2 = "Document_Open"
        $a3 = "Auto_Open"
        $a4 = "Workbook_Open"
        $s1 = "Shell(" ascii nocase
        $s2 = "CreateObject(" ascii nocase
    condition:
        filesize < 50MB and 1 of ($a*) and 1 of ($s*)
}

rule Generic_Cred_Dumper_Markers
{
    meta:
        author = "Malvex"
        description = "Generic cred-dumping markers (very conservative)"
        score = 70
        reference = "Heuristic"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "lsadump::sam" nocase
        $s3 = "mimikatz" nocase
    condition:
        filesize < 50MB and 1 of them
}

rule Suspicious_DLL_Load_Export
{
    meta:
        author = "Malvex"
        description = "Suspicious export names often used by loaders"
        score = 50
        reference = "Heuristic"
    strings:
        $e1 = "ReflectiveLoader"
        $e2 = "DllRegisterServer"
        $e3 = "DllInstall"
    condition:
        filesize < 50MB and pe.is_pe and 1 of them
}

rule MALVEX_TestMarker
{
    meta:
        description = "Benign test marker for Malvex"
        score = 100
    strings:
        $s = "MALVEX_TEST_TOKEN"
    condition:
        $s
}

/* Add further rules below, keeping filesize guard and conservative conditions */
