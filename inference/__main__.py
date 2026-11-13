import argparse
import logging
import os
from pathlib import Path

import uvicorn
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
from .app import create_inference_app

parser = argparse.ArgumentParser(description="Guarded local inference gateway")
parser.add_argument("--config", default="inference/litellm-config.yml")
parser.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1", "localhost", "::1"])
parser.add_argument("--port", type=int, default=4000)
args = parser.parse_args()
logging.disable(logging.CRITICAL)
uvicorn.run(create_inference_app(Path(args.config).resolve().parent.parent), host=args.host, port=args.port, access_log=False, log_level="warning")
