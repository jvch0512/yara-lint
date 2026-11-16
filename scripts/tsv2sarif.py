#!/usr/bin/env python3
"""Convert this tool's --tsv output into SARIF 2.1.0 for GitHub code scanning.

Usage: TOOL PATH --tsv | python3 scripts/tsv2sarif.py --tool NAME [--uri URL] [--prefix DIR] > results.sarif
Input rows: SEVERITY<TAB>RULE<TAB>WHERE<TAB>MESSAGE, with an optional first line "# N files, M findings".
Standard library only.
"""
import argparse, json, re, sys

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def parse(lines):
    for raw in lines:
        raw = raw.rstrip("\r\n")
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split("\t", 3)
        if len(parts) < 4:
            continue
        yield parts


def location(where, prefix=""):
    m = re.match(r"^(.*?):(\d+)(?::\d+)?$", where)
    path, line = (m.group(1), int(m.group(2))) if m else (where, 0)
    path = path.split("#", 1)[0].replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    path = (prefix.rstrip("/") + "/" + path) if prefix and not path.startswith("/") else path
    path = path or "."
    loc = {"physicalLocation": {"artifactLocation": {"uri": path}}}
    if line > 0:
        loc["physicalLocation"]["region"] = {"startLine": line}
    return loc


def convert(lines, tool, uri, prefix=""):
    rules, results = {}, []
    for sev, rule, where, msg in parse(lines):
        sev = sev.strip().lower()
        if rule not in rules:
            rules[rule] = {"id": rule, "name": rule, "shortDescription": {"text": msg[:120]},
                           "defaultConfiguration": {"level": LEVEL.get(sev, "warning")},
                           "properties": {"security-severity": SCORE.get(sev, "5.0")}}
        results.append({"ruleId": rule, "level": LEVEL.get(sev, "warning"), "message": {"text": msg},
                        "locations": [location(where, prefix)]})
    driver = {"name": tool, "informationUri": uri, "rules": list(rules.values())}
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": driver}, "results": results}]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", required=True)
    ap.add_argument("--uri", default="")
    ap.add_argument("--prefix", default="", help="directory that was scanned, so paths are relative to the repo root")
    ap.add_argument("file", nargs="?")
    a = ap.parse_args()
    src = open(a.file, encoding="utf-8", errors="replace") if a.file else sys.stdin
    uri = a.uri or f"https://github.com/jvch0512/{a.tool}"
    json.dump(convert(src, a.tool, uri, a.prefix), sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
