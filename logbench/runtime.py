"""Project-local detector wheels are separate from datasets."""
from pathlib import Path
import sys

RUNTIME=Path(__file__).resolve().parents[1]/'.runtime/detectors'
if RUNTIME.is_dir():
    sys.path.insert(0,str(RUNTIME))
