#!/usr/bin/env python3
"""Multi-core guard, run after setup-core (needs .core/).

Every method of sing-box's StartedService gRPC server must either be handled
by libbox's coreStartedService (so it answers sensibly while Xray or mihomo
runs) or be listed in libbox/core_grpc_passthrough.txt as reviewed: a
sing-box-only action the UI does not offer under the other cores. A sing-box
upgrade that adds a method fails here until someone decides which it is.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GRPC = ROOT / ".core/daemon/started_service_grpc.pb.go"
ALLOW = ROOT / "libbox/core_grpc_passthrough.txt"

source = GRPC.read_text()
block = re.search(r"type StartedServiceServer interface \{(.*?)\n\}", source, re.S)
if not block:
    sys.exit("StartedServiceServer interface not found in " + str(GRPC))
methods = [m for m in re.findall(r"^\s+([A-Z]\w*)\(", block.group(1), re.M)]
handled = set()
for path in (ROOT / "libbox").glob("*.go"):
    handled |= set(re.findall(r"func \(s \*coreStartedService\) (\w+)\(", path.read_text()))
allowed = {line.split("#")[0].strip() for line in ALLOW.read_text().splitlines()} - {""}

missing = [m for m in methods if m not in handled and m not in allowed]
stale = sorted(allowed - set(methods))
for method in missing:
    print(f"::error::StartedService.{method} is neither handled by coreStartedService nor listed in core_grpc_passthrough.txt")
for method in stale:
    print(f"::warning::core_grpc_passthrough.txt lists {method}, which sing-box no longer has")
print(f"{len(methods)} StartedService methods: {len(handled & set(methods))} handled, {len(allowed & set(methods))} reviewed pass-through")
sys.exit(1 if missing else 0)
