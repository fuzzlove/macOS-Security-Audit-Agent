# Python Support

Python 3.9 is a standard-library bootstrap and doctor runtime. Python 3.10–3.13 support CLI and GUI when dependencies pass preflight. Python 3.14 is headless-first; GUI is blocked unless explicitly qualified. Release packaging uses Python 3.12.

Use `python3 launcher.py`: Stage 0 selects a suitable interpreter without importing MSAA or Qt. Inspect decisions with `--print-python-selection`. Never install MSAA extras into Apple Command Line Tools Python.
