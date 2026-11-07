#!/usr/bin/env python3
"""Serve the multi-core gRPC wrapper (libbox/core_api.go) instead of the bare
sing-box StartedService, so the UI and remote control read Xray and mihomo
through the same interface."""
import sys
from pathlib import Path

core = Path(sys.argv[1])
path = core / "experimental/libbox/command_server.go"
text = path.read_text()
old = "daemon.RegisterStartedServiceServer(s.grpcServer, s.StartedService)"
new = "daemon.RegisterStartedServiceServer(s.grpcServer, &coreStartedService{s.StartedService})"
if new not in text:
    if text.count(old) != 1:
        sys.exit("patch_multicore: StartedService registration not found exactly once")
    path.write_text(text.replace(old, new))
