rule HopeLabs_C2_Configuration_Indicators
{
    meta:
        author = "Hope - HopeLabs Detection Engineering"
        description = "Identifies suspicious embedded command-and-control configuration indicators"
        category = "Command and Control Detection"
        severity = "High"
        confidence = "Medium"
        date = "2026-11-06"
        version = "2.0"
        mitre_attack = "T1071.001, T1105, T1573"
        reference = "https://attack.mitre.org/"

    strings:
        // HTTP communication indicators
        $http1 = "User-Agent:" ascii wide nocase
        $http2 = "Host:" ascii wide nocase
        $http3 = "POST /" ascii wide nocase
        $http4 = "GET /" ascii wide nocase

        // URL and configuration indicators
        $url1 = "http://" ascii wide nocase
        $url2 = "https://" ascii wide nocase
        $config1 = "command_and_control" ascii wide nocase
        $config2 = "beacon_interval" ascii wide nocase
        $config3 = "callback_url" ascii wide nocase
        $config4 = "c2_server" ascii wide nocase

        // Common communication paths
        $path1 = "/gate.php" ascii wide nocase
        $path2 = "/panel/" ascii wide nocase
        $path3 = "/api/checkin" ascii wide nocase
        $path4 = "/update/" ascii wide nocase

        // Harmless lab-testing marker
        $test1 = "HOPELABS_C2_TEST_MARKER" ascii

    condition:
        filesize < 10MB and
        (
            (
                2 of ($config*) and
                1 of ($url*)
            )
            or
            (
                2 of ($path*) and
                1 of ($http*)
            )
            or
            (
                2 of ($http*) and
                1 of ($config*)
            )
            or
            $test1
        )
}
