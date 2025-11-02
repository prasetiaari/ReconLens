"""
Legacy Targets Router Entry
---------------------------

This module is now minimal — it only provides constants and backward
compatibility for external references.
"""

from fastapi import APIRouter
from pathlib import Path

# Global constants
BASE_DIR = Path(__file__).resolve().parents[2]
OUTPUTS_DIR = BASE_DIR / "outputs"

router = APIRouter(prefix="/targets", tags=["Targets"])