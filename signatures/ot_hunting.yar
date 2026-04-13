rule ICS_OT_Protocol_Detection {
    meta:
        description = "Detects Industrial protocols and Engineering strings with size constraints"
        author = "404saint"
        priority = "CRITICAL"

    strings:
        /* Modbus TCP: Look for the '00 00' Protocol ID in the header */
        $modbus_tcp = { 00 00 00 00 00 ?? ?? } 

        /* S7Comm: Protocol ID '32' and ROSCTR '01' or '07' */
        $s7comm = { 32 0[17] 00 00 }

        /* Ethernet/IP & CIP: Common session headers */
        $ethernet_ip = { 65 00 ?? ?? 00 00 00 00 }

        /* Engineering Keywords - Requiring 2+ to reduce false positives */
        $eng1 = "Step7" nocase
        $eng2 = "TIA Portal" nocase
        $eng3 = "Studio 5000" nocase
        $eng4 = "Logic Download" nocase

    condition:
        /* Rule 1: Any Hex Protocol Pattern is an immediate hit */
        any of ($modbus_tcp, $s7comm, $ethernet_ip) or 
        
        /* Rule 2: If it's a small file (< 100KB) and mentions an OT protocol */
        (filesize < 100KB and (any of ($eng*))) or

        /* Rule 3: Multiple keywords found in one file */
        2 of ($eng*)
}