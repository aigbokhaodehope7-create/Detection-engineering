rule HopeLabs_Suspicious_PowerShell_Execution
{
    meta:
        author = "Hope - HopeLabs Detection Engineering"
        description = "Detects suspicious PowerShell script patterns associated with encoded execution, download activity, obfuscation and defense evasion"
        category = "PowerShell Detection"
        severity = "High"
        confidence = "Medium"
        date = "2026-11-06"
        version = "2.0"
        mitre_attack = "T1059.001, T1027, T1105"
        reference = "https://attack.mitre.org/"

    strings:
        // Encoded command execution
        $encoded1 = "-EncodedCommand" ascii wide nocase
        $encoded2 = "-enc " ascii wide nocase
        $encoded3 = "FromBase64String" ascii wide

        // Dynamic code execution
        $exec1 = "Invoke-Expression" ascii wide nocase
        $exec2 = "IEX" ascii wide nocase
        $exec3 = "ScriptBlock" ascii wide nocase

        // Download activity
        $download1 = "DownloadString" ascii wide
        $download2 = "DownloadFile" ascii wide
        $download3 = "Invoke-WebRequest" ascii wide nocase
        $download4 = "Net.WebClient" ascii wide

        // Defense evasion indicators
        $evasion1 = "ExecutionPolicy Bypass" ascii wide nocase
        $evasion2 = "WindowStyle Hidden" ascii wide nocase
        $evasion3 = "amsiInitFailed" ascii wide nocase
        $evasion4 = "AmsiUtils" ascii wide

        // Reconnaissance indicators
        $recon1 = "Get-LocalUser" ascii wide nocase
        $recon2 = "Get-Process" ascii wide nocase
        $recon3 = "Get-NetIPAddress" ascii wide nocase

        // Harmless testing marker
        $test1 = "HOPELABS_POWERSHELL_TEST_MARKER" ascii

    condition:
        filesize < 2MB and
        (
            (
                1 of ($encoded*) and
                1 of ($exec*)
            )
            or
            (
                2 of ($download*) and
                1 of ($exec*)
            )
            or
            (
                2 of ($evasion*) and
                1 of ($exec*)
            )
            or
            (
                2 of ($recon*) and
                1 of ($encoded*)
            )
            or
            $test1
        )
}
