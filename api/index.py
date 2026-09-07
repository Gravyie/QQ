"""Vercel Serverless Function entry point for Quantum Atlas."""
import os
import sys
from pathlib import Path

# Add backend directory to Python path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'backend'))

# Use /tmp for writable scan outputs in serverless environments
if os.environ.get('VERCEL'):
    os.environ.setdefault('RESULTS_DIR', '/tmp/results')

from server import app
