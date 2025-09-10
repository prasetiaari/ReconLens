from __future__ import annotations
import os
from pathlib import Path
from pydantic import BaseModel

MODULE_FILEMAP = {
    "subdomains": "subdomains.txt",
    "sensitive_paths": "sensitive_paths.txt",
    "open_redirect": "open_redirect_candidates.txt",
    "documents": "documents.txt",
    "sensitive_params": "sensitive_params.txt",
    "jwt_candidates": "jwt_candidates.txt",
    "params": "params.txt",
    "params_urls": "params_urls.txt",
    "robots": "robots_urls.txt",
    "emails": "emails_urls.txt",
}

class Settings(BaseModel):
    BASE_DIR: Path = Path(__file__).resolve().parent
    APP_DIR: Path = BASE_DIR
    ROOT_DIR: Path = BASE_DIR.parent

    OUTPUTS_DIR: Path = Path(os.getenv("OUTPUTS_DIR", BASE_DIR.parent / "outputs"))
    STATIC_DIR: Path = Path(os.getenv("STATIC_DIR", APP_DIR / "static"))
    TEMPLATES_DIR: Path = Path(os.getenv("TEMPLATES_DIR", APP_DIR / "templates"))

    PAGE_SIZE_DEFAULT: int = int(os.getenv("PAGE_SIZE", "100"))
    PAGE_SIZE_MAX: int = 1000

    MODULES: dict = MODULE_FILEMAP

    class Config:
        arbitrary_types_allowed = True
