# app/core/settings.py
from pathlib import Path

class Settings:
    OUTPUTS_DIR = Path("outputs")
    MODULES = {}

# singleton sederhana
_settings = Settings()

def get_settings(request=None) -> Settings:
    return _settings
