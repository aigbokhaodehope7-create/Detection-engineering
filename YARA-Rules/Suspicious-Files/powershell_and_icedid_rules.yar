rule Suspicious_PowerShell_Download_Cradle
{
    meta:
        author = "Aigbokhaode Hope Imomoh"
        description = "Suspicious PowerShell download/execution patterns - needs analyst validation"
        date = "2026-11-12"
        category = "PowerShell"
    strings:
        $ps1    = "powershell.exe"          nocase ascii wide
        $evade1 = "-EncodedCommand"         nocase ascii wide
        $evade2 = "-ExecutionPolicy Bypass" nocase ascii wide
        $exec1 = "IEX" fullword             nocase ascii wide
        $exec2 = "Invoke-Expression"        nocase ascii wide
        $dl1    = "DownloadString"          nocase ascii wide
        $dl2    = "Net.WebClient"           nocase ascii wide
        $dl3    = "Invoke-WebRequest"       nocase ascii wide
        $dl4    = "Start-BitsTransfer"      nocase ascii wide
        $b64    = "FromBase64String"        nocase ascii wide
    condition:
        filesize < 1MB and $ps1 and
        1 of ($evade*) and 1 of ($dl*, $exec*, $b64)
}
