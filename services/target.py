# services/target.py
"""
Target management service.

Handles target lifecycle:
- Creating new targets
- Listing targets
- Target metadata
- Target deletion
"""

from __future__ import annotations

from typing import List, Dict, Any, Optional

from storage.base import BaseStorage
from core.types import Target
from core.exceptions import TargetNotFoundError, TargetExistsError


class TargetService:
    """
    Service for managing recon targets.
    
    Handles CRUD operations for targets and their metadata.
    """
    
    def __init__(self, storage: BaseStorage):
        """
        Initialize target service.
        
        Args:
            storage: Storage backend instance
        """
        self.storage = storage
    
    def list_targets(self) -> List[Dict[str, Any]]:
        """
        List all targets with summary info.
        
        Returns:
            List of target info dicts with:
            - scope: Target domain
            - url_count: Number of collected URLs
            - subdomain_count: Number of subdomains
            - analysis_count: Number of analyses run
        """
        targets = []
        
        for scope in self.storage.list_scopes():
            info = self.get_target_info(scope)
            targets.append(info)
        
        return targets
    
    def get_target_info(self, scope: str) -> Dict[str, Any]:
        """
        Get detailed info for a target.
        
        Args:
            scope: Target scope
            
        Returns:
            Dict with target details
        """
        if not self.storage.scope_exists(scope):
            raise TargetNotFoundError(scope)
        
        # Count URLs
        url_count = 0
        if self.storage.urls_exist(scope, "urls"):
            url_count = self.storage.url_count(scope, "urls")
        
        # Count subdomains
        subdomain_count = 0
        if self.storage.urls_exist(scope, "subdomains"):
            subdomain_count = self.storage.url_count(scope, "subdomains")
        
        # List analyses
        analyses = self.storage.list_analyses(scope)
        
        return {
            "scope": scope,
            "url_count": url_count,
            "subdomain_count": subdomain_count,
            "analysis_count": len(analyses),
            "analyses": analyses,
        }
    
    def create_target(self, scope: str, metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Create a new target.
        
        Args:
            scope: Target domain
            metadata: Optional metadata
            
        Returns:
            Created target info
            
        Raises:
            TargetExistsError: If target already exists
        """
        scope = scope.lower().strip()
        
        if self.storage.scope_exists(scope):
            raise TargetExistsError(scope)
        
        self.storage.create_scope(scope)
        
        # Save metadata if provided
        if metadata:
            self.storage.save_json(scope, "target_meta", metadata)
        
        return self.get_target_info(scope)
    
    def delete_target(self, scope: str) -> None:
        """
        Delete a target and all its data.
        
        Args:
            scope: Target scope
            
        Raises:
            TargetNotFoundError: If target doesn't exist
        """
        if not self.storage.scope_exists(scope):
            raise TargetNotFoundError(scope)
        
        self.storage.delete_scope(scope)
    
    def target_exists(self, scope: str) -> bool:
        """Check if target exists."""
        return self.storage.scope_exists(scope)
    
    def get_target(self, scope: str) -> Target:
        """
        Get Target object for a scope.
        
        Args:
            scope: Target scope
            
        Returns:
            Target object with config
            
        Raises:
            TargetNotFoundError: If target doesn't exist
        """
        if not self.storage.scope_exists(scope):
            raise TargetNotFoundError(scope)
        
        # Load metadata if exists
        metadata = self.storage.load_json(scope, "target_meta") or {}
        
        return Target(
            scope=scope,
            include_external=metadata.get("include_external", False),
            allow_subdomains=metadata.get("allow_subdomains", []),
            deny_subdomains=metadata.get("deny_subdomains", []),
            metadata=metadata,
        )
    
    def update_target_config(
        self,
        scope: str,
        include_external: Optional[bool] = None,
        allow_subdomains: Optional[List[str]] = None,
        deny_subdomains: Optional[List[str]] = None,
    ) -> Target:
        """
        Update target configuration.
        
        Args:
            scope: Target scope
            include_external: Whether to include external URLs
            allow_subdomains: Glob patterns to allow
            deny_subdomains: Glob patterns to deny
            
        Returns:
            Updated Target object
        """
        if not self.storage.scope_exists(scope):
            raise TargetNotFoundError(scope)
        
        # Load existing
        metadata = self.storage.load_json(scope, "target_meta") or {}
        
        # Update
        if include_external is not None:
            metadata["include_external"] = include_external
        if allow_subdomains is not None:
            metadata["allow_subdomains"] = allow_subdomains
        if deny_subdomains is not None:
            metadata["deny_subdomains"] = deny_subdomains
        
        # Save
        self.storage.save_json(scope, "target_meta", metadata)
        
        return self.get_target(scope)
