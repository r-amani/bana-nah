"""
PHANTOM Global Pytest Configuration and Fixtures
Ensures deterministic event loops, prevents network hangs, and provides mock cleanups.
"""
import asyncio
import os
import sys
import pytest

# Ensure backend root is on sys.path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# On Windows, set WindowsSelectorEventLoopPolicy to prevent IOCP socketpair hangs
if sys.platform == "win32":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass




