/*
 * Malitious batch script detection
 * Github: https://www.github.com/0x4248/YARA-Rules
 * Licence: GNU General Public License v3.0
 * By: 0x4248
*/

import "magic"

rule batch_wipe_32 {
    meta:
        name = "Detect batch system32 wiper"
        author = "Lewis Evans"
        description = "Detects batch scripts that wipe the system32 folder"
        extension = ".bat .cmd"
        date = "2023-04-17"
    strings:
        $wiper = "del C:\\windows\\system32"
    condition:
        $wiper
}