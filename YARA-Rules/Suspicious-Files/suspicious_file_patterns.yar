import "pe"

rule HopeLabs_Suspicious_File_Characteristics
{
    meta:
        author = "Hope - HopeLabs Detection Engineering"
        description = "Identifies suspicious file characteristics, embedded scripts and potentially misleading file content"
        category = "Suspicious File Detection"
        severity = "Medium"
        confidence = "Medium"
        date = "2026-11-06"
        version = "2.0"
        mitre_attack = "T1036, T1027, T1204.002"
        reference = "https://attack.mitre.org/"

    strings:
        // Suspicious script execution indicators
        $script1 = "powershell.exe" ascii wide nocase
        $script2 = "wscript.exe" ascii wide nocase
        $script3 = "cscript.exe" ascii wide nocase
        $script4 = "mshta.exe" ascii wide nocase

        // Embedded script indicators
        $script5 = "WScript.Shell" ascii wide
        $script6 = "Shell.Application" ascii wide
        $script7 = "CreateObject" ascii wide

        // Archive and payload indicators
        $archive1 = "PK" 
        $archive2 = "MZ"
        $payload1 = "This program cannot be run in DOS mode" ascii

        // Suspicious naming and execution hints
        $name1 = "invoice" ascii wide nocase
        $name2 = "payment" ascii wide nocase
        $name3 = "document" ascii wide nocase

        // Harmless lab-testing marker
        $test1 = "HOPELABS_SUSPICIOUS_FILE_TEST_MARKER" ascii

    condition:
        filesize > 0 and
        filesize < 20MB and
        (
            (
                2 of ($script*) and
                1 of ($script5, $script6, $script7)
            )
            or
            (
                $payload1 and
                1 of ($script*)
            )
            or
            (
                $test1
            )
        )
}
