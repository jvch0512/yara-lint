import "pe"

rule Mimikatz_Strings : credential_theft
{
    meta:
        description = "Detects strings used by Mimikatz"
        author = "Example Team"
    strings:
        $a = "sekurlsa::logonpasswords" ascii wide nocase
        $b = "gentilkiwi" ascii wide
        $c = { 6D 69 6D 69 6B 61 74 7A }
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($a, $b, $c)
}
