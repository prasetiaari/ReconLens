from __future__ import annotations
from typing import Dict, List, Generic, TypeVar
from pydantic import BaseModel

class Summary(BaseModel):
    scope: str
    counts: Dict[str, int] = {}
    generated_at: str | None = None

class ModuleStat(BaseModel):
    module: str
    file: str
    size_bytes: int
    lines: int

T = TypeVar("T")

class Page(BaseModel, Generic[T]):
    items: List[T]
    page: int
    page_size: int
    total: int
    has_next: bool

class RowUrl(BaseModel):
    url: str
