# app/routers/api_v2/targets.py
"""
Target management API v2.

Uses new TargetService for clean separation of concerns.
"""

from __future__ import annotations

from typing import Dict, List, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Body
from pydantic import BaseModel, Field

from app.deps import get_target_service_from_request
from services.target import TargetService
from core.exceptions import TargetNotFoundError, TargetExistsError


router = APIRouter(prefix="/targets", tags=["targets-v2"])


# ==================== Request/Response Models ====================

class TargetCreate(BaseModel):
    """Request model for creating a target."""
    scope: str = Field(..., description="Target domain (e.g., 'example.com')")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Optional metadata")


class TargetUpdate(BaseModel):
    """Request model for updating target config."""
    include_external: Optional[bool] = None
    allow_subdomains: Optional[List[str]] = None
    deny_subdomains: Optional[List[str]] = None


class TargetInfo(BaseModel):
    """Response model for target info."""
    scope: str
    url_count: int
    subdomain_count: int
    analysis_count: int
    analyses: List[str]


class TargetList(BaseModel):
    """Response model for target list."""
    targets: List[TargetInfo]
    total: int


# ==================== Endpoints ====================

@router.get("", response_model=TargetList)
def list_targets(
    service: TargetService = Depends(get_target_service_from_request)
):
    """
    List all targets with summary info.
    
    Returns count of URLs, subdomains, and analyses for each target.
    """
    targets = service.list_targets()
    return TargetList(targets=targets, total=len(targets))


@router.get("/{scope}", response_model=TargetInfo)
def get_target(
    scope: str,
    service: TargetService = Depends(get_target_service_from_request)
):
    """
    Get detailed info for a specific target.
    
    Args:
        scope: Target domain
    """
    try:
        return service.get_target_info(scope)
    except TargetNotFoundError as e:
        raise HTTPException(status_code=404, detail=e.to_dict())


@router.post("", response_model=TargetInfo, status_code=201)
def create_target(
    body: TargetCreate,
    service: TargetService = Depends(get_target_service_from_request)
):
    """
    Create a new target.
    
    Args:
        body: Target creation data
    """
    try:
        return service.create_target(body.scope, body.metadata)
    except TargetExistsError as e:
        raise HTTPException(status_code=409, detail=e.to_dict())


@router.patch("/{scope}")
def update_target(
    scope: str,
    body: TargetUpdate,
    service: TargetService = Depends(get_target_service_from_request)
):
    """
    Update target configuration.
    
    Args:
        scope: Target domain
        body: Fields to update
    """
    try:
        target = service.update_target_config(
            scope,
            include_external=body.include_external,
            allow_subdomains=body.allow_subdomains,
            deny_subdomains=body.deny_subdomains,
        )
        return {
            "scope": target.scope,
            "include_external": target.include_external,
            "allow_subdomains": target.allow_subdomains,
            "deny_subdomains": target.deny_subdomains,
        }
    except TargetNotFoundError as e:
        raise HTTPException(status_code=404, detail=e.to_dict())


@router.delete("/{scope}", status_code=204)
def delete_target(
    scope: str,
    service: TargetService = Depends(get_target_service_from_request)
):
    """
    Delete a target and all its data.
    
    Args:
        scope: Target domain
    """
    try:
        service.delete_target(scope)
    except TargetNotFoundError as e:
        raise HTTPException(status_code=404, detail=e.to_dict())
