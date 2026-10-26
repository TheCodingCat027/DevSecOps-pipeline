# Root conftest.py — adds the repo root to sys.path so pytest can import contracts.validate
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
