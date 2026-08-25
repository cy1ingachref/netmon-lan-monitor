"""run.py - root-level entry point.

Lets you run netmon without installing the package:
    python run.py scan
    python run.py sniff --with-demo 20
    python run.py web
Same as `python -m netmon`, but avoids needing PYTHONPATH set.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netmon.cli import main

if __name__ == "__main__":
    main()
