"""netmon - local network & traffic monitor (CLI entry point).

Package supports both ``python -m netmon`` and direct execution (the
``sys.path`` insertion below keeps development-time direct runs working).
All command logic lives in ``netmon.cli``.
"""
from netmon.cli import main

if __name__ == "__main__":
    main()
