/*
 * Guloader malware detection rule
 * Github: https://www.github.com/0x4248/YARA-Rules
 * Licence: GNU General Public License v3.0
 * By: 0x4248
*/

rule WIN_PE_identifier {
    meta:
        description = "Windows PE identifier"
        author = "Lewis Evans"
        date = "2023-04-17"
    strings:
        $pe = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 }
        $dos_message = "This program cannot be run in DOS mode"
    condition:
        $pe at 0 and $dos_message
}

rule Guloader {
    meta:
        author = "Lewis Evans"
        description = "Guloader malware"
        date = "2023-04-17"
    strings:
        $gu1 = "D$TmL@"
        $gu2 = "D$$vS@"
    condition:
        WIN_PE_identifier and ($gu1 or $gu2)
}