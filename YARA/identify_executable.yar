/*
 * Rule to detect GCC ELF binaries and Windows PE binaries
 * Github: https://www.github.com/awesomelewis2007/YARA-Rules
 * Licence: GNU General Public License v3.0
 * By Lewis Evans
*/

rule GCC_ELF_identifer {
    meta:
        description = "GCC ELF identifier"
        author = "Lewis Evans"
        date = "2023-04-17"
    strings:
        $elf = { 7f 45 4c 46 }
        $gcc = "GCC"
    condition:
        $elf at 0 and $gcc
}

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