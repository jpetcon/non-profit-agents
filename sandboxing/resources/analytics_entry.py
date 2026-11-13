"""Run the installed maintained connector, honouring SRT's proxy variables."""
import importlib.metadata
import os

os.environ["grpc_proxy"] = os.environ.get("https_proxy", os.environ.get("HTTPS_PROXY", ""))
entry = next(e for e in importlib.metadata.distribution("analytics-mcp").entry_points if e.group == "console_scripts" and e.name == "analytics-mcp")
entry.load()()
