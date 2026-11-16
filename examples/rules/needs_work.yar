// rules with problems
rule Mimikatz_Strings
{
    strings:
        $a = "mz"
        $a = "sekurlsa"
        $b = /http:\/\/.*\.exe/
        $c = { ?? 4D 5A }
        $d = "unused-string-here"
    condition:
        $a and $b and $c and $missing
}

rule No_Condition
{
    meta:
        description = "forgot the condition"
        author = "Example Team"
    strings:
        $x = "something-long-enough"
}

rule Match_Everything
{
    meta:
        description = "always fires"
        author = "Example Team"
    condition:
        true
}

rule Wildcard_Refs {
    meta: description = "ok" author = "x"
    strings: $s1 = "first-string" $s2 = "second-string"
    condition: filesize < 1MB and any of ($s*)
}
