#!/usr/bin/env python3
"""Bump one core in version.properties, after checking it can build here.

    python3 tools/bump_core.py sing-box 1.15.0-alpha.14
    python3 tools/bump_core.py xray 26.8.1
    python3 tools/bump_core.py mihomo 1.19.34
    python3 tools/bump_core.py libxray v1.260801.0
    python3 tools/bump_core.py ... --dry-run     # only report

Checks before writing: the tag exists, the module resolves on the Go proxy
(Xray tags are not valid module versions, so the tag's commit is turned into
the pseudo-version Go uses), and the go directive of the new go.mod is not
newer than GO_VERSION (a newer one breaks setup-core). Only version.properties
changes; build and test on a branch (see "升级内核" in libbox.md).
"""
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROPS = ROOT / "version.properties"


def get(url):
    request = urllib.request.Request(url, headers={"User-Agent": "b-box-bump-core"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode()


def read_props():
    props = {}
    for line in PROPS.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            props[key.strip()] = value.strip()
    return props


def write_props(changes):
    lines = PROPS.read_text().splitlines()
    for index, line in enumerate(lines):
        key = line.split("=", 1)[0].strip()
        if key in changes:
            lines[index] = f"{key}={changes[key]}"
    PROPS.write_text("\n".join(lines) + "\n")


def go_tuple(version):
    return tuple(int(part) for part in re.findall(r"\d+", version)[:3])


def go_directive(mod_text):
    match = re.search(r"^go\s+(\S+)", mod_text, re.M)
    return match.group(1) if match else "0"


def proxy(module, suffix):
    return get(f"https://proxy.golang.org/{module.lower()}/@v/{suffix}")


def tag_commit(repo, tag):
    ref = json.loads(get(f"https://api.github.com/repos/{repo}/git/ref/tags/{tag}"))
    obj = ref["object"]
    if obj["type"] == "tag":  # annotated tag
        obj = json.loads(get(obj["url"]))["object"]
    return obj["sha"]


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    core, version = argv[0], argv[1]
    dry = "--dry-run" in argv
    props = read_props()
    go_version = props["GO_VERSION"].removeprefix("go")
    changes = {}
    if core == "sing-box":
        version = version.removeprefix("v")
        mod = get(f"https://raw.githubusercontent.com/SagerNet/sing-box/v{version}/go.mod")
        changes["CORE_VERSION"] = version
    elif core == "xray":
        version = version.removeprefix("v")
        sha = tag_commit("XTLS/Xray-core", f"v{version}")
        info = json.loads(proxy("github.com/xtls/xray-core", f"{sha}.info"))
        mod = proxy("github.com/xtls/xray-core", f"{info['Version']}.mod")
        changes["XRAY_VERSION"] = version
        changes["XRAY_MODULE_VERSION"] = info["Version"]
    elif core == "mihomo":
        version = version.removeprefix("v")
        mod = proxy("github.com/metacubex/mihomo", f"v{version}.mod")
        changes["MIHOMO_VERSION"] = version
    elif core == "libxray":
        version = "v" + version.removeprefix("v")
        mod = proxy("github.com/xtls/libxray", f"{version}.mod")
        changes["LIBXRAY_MODULE_VERSION"] = version
    else:
        print(f"unknown core {core}; use sing-box, xray, mihomo or libxray")
        return 2
    needs = go_directive(mod)
    print(f"{core} {version}: go.mod needs go {needs}; build uses go {go_version}")
    for key, value in changes.items():
        print(f"  {key}: {props.get(key, '')} -> {value}")
    if go_tuple(needs) > go_tuple(go_version):
        print("Refusing: the new version needs a newer Go than GO_VERSION. "
              "Raise GO_VERSION on its own first (all three cores must build with it).")
        return 1
    if core == "xray":
        print("Also check libXray: its go.mod must accept this xray-core "
              "(python3 tools/bump_core.py libxray <version> if it needs a newer one).")
    if dry:
        print("dry run: nothing written")
        return 0
    write_props(changes)
    print("version.properties updated. Next: branch, CI (build-debug-apk), device checklist.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
