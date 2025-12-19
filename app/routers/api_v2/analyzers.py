# app/routers/api_v2/analyzers.py
"""
Analyzer API v2.

Uses new AnalysisService for running analyzers and managing results.
"""

from __future__ import annotations

from typing import Dict, List, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from app.deps import get_analysis_service_from_request, get_storage_from_request
from services.analysis import AnalysisService
from storage.base import BaseStorage
from core.exceptions import TargetNotFoundError, AnalyzerNotFoundError
from analyzers import list_analyzers, get_analyzer_info


router = APIRouter(prefix="/analyzers", tags=["analyzers-v2"])


# ==================== Response Models ====================

class AnalyzerInfo(BaseModel):
    """Info about an analyzer."""
    name: str
    description: str
    output_filename: str


class AnalysisResultResponse(BaseModel):
    """Response for analysis results."""
    analyzer_name: str
    match_count: int
    total_processed: int
    match_rate: float
    timestamp: Optional[str] = None


class AnalysisRunResponse(BaseModel):
    """Response after running an analyzer."""
    status: str = "completed"
    analyzer_name: str
    match_count: int
    total_processed: int
    match_rate: float


class UrlListResponse(BaseModel):
    """Response with URL list."""
    analyzer_name: str
    urls: List[str]
    total: int
    offset: int
    limit: int


# ==================== Endpoints ====================

@router.get("", response_model=List[AnalyzerInfo])
def get_available_analyzers():
    """
    List all available analyzers.
    
    Returns info about each registered analyzer.
    """
    return get_analyzer_info()


@router.get("/{scope}/results", response_model=List[AnalysisResultResponse])
def list_analysis_results(
    scope: str,
    service: AnalysisService = Depends(get_analysis_service_from_request)
):
    """
    List all analysis results for a target.
    
    Args:
        scope: Target domain
    """
    try:
        return service.list_analyses(scope)
    except TargetNotFoundError as e:
        raise HTTPException(status_code=404, detail=e.to_dict())


@router.get("/{scope}/{analyzer_name}", response_model=AnalysisResultResponse)
def get_analysis_result(
    scope: str,
    analyzer_name: str,
    service: AnalysisService = Depends(get_analysis_service_from_request)
):
    """
    Get specific analysis result.
    
    Args:
        scope: Target domain
        analyzer_name: Name of analyzer
    """
    result = service.get_analysis_result(scope, analyzer_name)
    if not result:
        raise HTTPException(status_code=404, detail={
            "error": "AnalysisNotFound",
            "message": f"No results for analyzer '{analyzer_name}' on '{scope}'"
        })
    
    return AnalysisResultResponse(
        analyzer_name=result.analyzer_name,
        match_count=result.match_count,
        total_processed=result.total_processed,
        match_rate=round(result.match_rate, 2),
        timestamp=result.timestamp,
    )


@router.get("/{scope}/{analyzer_name}/urls", response_model=UrlListResponse)
def get_analysis_urls(
    scope: str,
    analyzer_name: str,
    offset: int = 0,
    limit: int = 100,
    q: Optional[str] = None,
    storage: BaseStorage = Depends(get_storage_from_request)
):
    """
    Get URLs from analysis result with pagination.
    
    Args:
        scope: Target domain
        analyzer_name: Name of analyzer
        offset: Pagination offset
        limit: Max results (max 1000)
        q: Optional search filter
    """
    if limit > 1000:
        limit = 1000
    
    if not storage.scope_exists(scope):
        raise HTTPException(status_code=404, detail={
            "error": "TargetNotFound",
            "message": f"Target not found: {scope}"
        })
    
    # Load URLs
    all_urls = list(storage.iter_urls(scope, analyzer_name))
    
    # Filter if query provided
    if q:
        q_lower = q.lower()
        all_urls = [u for u in all_urls if q_lower in u.lower()]
    
    total = len(all_urls)
    urls = all_urls[offset:offset + limit]
    
    return UrlListResponse(
        analyzer_name=analyzer_name,
        urls=urls,
        total=total,
        offset=offset,
        limit=limit,
    )


@router.post("/{scope}/{analyzer_name}/run", response_model=AnalysisRunResponse)
def run_analyzer(
    scope: str,
    analyzer_name: str,
    input_name: str = "urls",
    service: AnalysisService = Depends(get_analysis_service_from_request)
):
    """
    Run a specific analyzer on target.
    
    Args:
        scope: Target domain
        analyzer_name: Name of analyzer to run
        input_name: Input URL file (default: "urls")
    """
    try:
        result = service.run_analyzer(scope, analyzer_name, input_name)
        return AnalysisRunResponse(
            status="completed",
            analyzer_name=result.analyzer_name,
            match_count=result.match_count,
            total_processed=result.total_processed,
            match_rate=round(result.match_rate, 2),
        )
    except TargetNotFoundError as e:
        raise HTTPException(status_code=404, detail=e.to_dict())
    except AnalyzerNotFoundError as e:
        raise HTTPException(status_code=404, detail=e.to_dict())


@router.post("/{scope}/run-all", response_model=List[AnalysisRunResponse])
def run_all_analyzers(
    scope: str,
    input_name: str = "urls",
    service: AnalysisService = Depends(get_analysis_service_from_request)
):
    """
    Run all analyzers on target.
    
    Args:
        scope: Target domain
        input_name: Input URL file (default: "urls")
    """
    try:
        results = service.run_all_analyzers(scope, input_name)
        return [
            AnalysisRunResponse(
                status="completed",
                analyzer_name=r.analyzer_name,
                match_count=r.match_count,
                total_processed=r.total_processed,
                match_rate=round(r.match_rate, 2),
            )
            for r in results
        ]
    except TargetNotFoundError as e:
        raise HTTPException(status_code=404, detail=e.to_dict())


@router.delete("/{scope}/{analyzer_name}", status_code=204)
def delete_analysis(
    scope: str,
    analyzer_name: str,
    service: AnalysisService = Depends(get_analysis_service_from_request)
):
    """
    Delete analysis result.
    
    Args:
        scope: Target domain
        analyzer_name: Name of analyzer
    """
    service.delete_analysis(scope, analyzer_name)
