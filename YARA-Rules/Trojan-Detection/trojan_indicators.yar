import "pe"

rule HopeLabs_Trojan_Suspicious_Execution_Indicators
{
    meta:
        author = "Hope - HopeLabs Detection Engineering"
        description = "Identifies Windows PE files containing combinations of suspicious execution, persistence and process manipulation indicators"
        category = "Trojan Detection"
        severity = "High"
        confidence = "Medium"
        date = "2026-11-06"
        version = "2.0"
        mitre_attack = "T1055, T1547.001, T1105"
        reference = "https://attack.mitre.org/"

    strings:
        // Process manipulation APIs
        $process1 = "OpenProcess" ascii wide
        $process2 = "WriteProcessMemory" ascii wide
        $process3 = "CreateRemoteThread" ascii wide
        $process4 = "VirtualAllocEx" ascii wide

        // Persistence-related indicators
        $persist1 = "CurrentVersion\\Run" ascii wide nocase
        $persist2 = "CurrentVersion\\RunOnce" ascii wide nocase
        $persist3 = "schtasks.exe" ascii wide nocase
        $persist4 = "Startup" ascii wide nocase

        // Payload retrieval and execution
        $download1 = "URLDownloadToFile" ascii wide
        $download2 = "InternetOpenUrl" ascii wide
        $download3 = "WinHttpSendRequest" ascii wide

        // Suspicious execution indicators
        $exec1 = "ShellExecute" ascii wide
        $exec2 = "WinExec" ascii wide
        $exec3 = "CreateProcess" ascii wide

        // Harmless lab-testing marker
        $test1 = "HOPELABS_TROJAN_TEST_MARKER" ascii

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        filesize > 10KB and
        (
            (
                2 of ($process*) and
                1 of ($persist*)
            )
            or
            (
                2 of ($download*) and
                1 of ($exec*)
            )
            or
            (
                1 of ($process*) and
                2 of ($persist*) and
                1 of ($exec*)
            )
            or
            $test1
        )
}
