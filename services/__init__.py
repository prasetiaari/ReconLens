# services/__init__.py
"""
Service layer for business logic orchestration.

Services coordinate between:
- Storage layer (data persistence)
- Analyzers (URL classification)
- External tools (gau, subfinder, etc.)
- AI/LLM (classification)

This layer is what the web/CLI interfaces talk to.

Usage:
    from services import AnalysisService, TargetService
    from storage import FileStorage
    
    storage = FileStorage()
    analysis_service = AnalysisService(storage)
    
    result = analysis_service.run_analyzer("example.com", "open_redirect")
"""

from services.analysis import AnalysisService
from services.target import TargetService

__all__ = [
    "AnalysisService",
    "TargetService",
]
