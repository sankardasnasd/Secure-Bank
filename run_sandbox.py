
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from myapp.sandbox_engine import run_standalone_server


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000

    print("=" * 70)
    print("Standalone Sandbox API")
    print(f"API:    http://127.0.0.1:{port}/analyze")
    print(f"Status: http://127.0.0.1:{port}/status")
    print("=" * 70)

    run_standalone_server(port=port)