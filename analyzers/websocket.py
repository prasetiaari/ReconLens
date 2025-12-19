# analyzers/websocket.py
"""
WebSocket Endpoints analyzer.

Detects URLs that use WebSocket protocol.
"""

from __future__ import annotations

import re
from typing import Dict, Any, Optional

from analyzers.base import BaseAnalyzer
from analyzers import register
from core.types import ParsedURL


@register
class WebSocketAnalyzer(BaseAnalyzer):
    """
    Detect WebSocket endpoints.
    
    Matches URLs with WebSocket-related paths or patterns.
    """
    
    # WebSocket path patterns
    WS_PATH_PATTERNS = [
        r"/ws",
        r"/wss",
        r"/websocket",
        r"/socket",
        r"/socket\.io",
        r"/sockjs",
        r"/signalr",
        r"/hub",
        r"/hubs",
        r"/realtime",
        r"/live",
        r"/stream",
        r"/push",
        r"/notification",
        r"/events",
        r"/cable",
        r"/graphql-ws",
    ]
    
    RE_WS_PATTERNS = [re.compile(p, re.I) for p in WS_PATH_PATTERNS]
    
    @property
    def name(self) -> str:
        return "websocket"
    
    @property
    def description(self) -> str:
        return "Detect WebSocket endpoints"
    
    @property
    def output_filename(self) -> str:
        return "websocket_endpoints.txt"
    
    def should_include(self, parsed: ParsedURL) -> bool:
        """Check if URL is a WebSocket endpoint."""
        for pattern in self.RE_WS_PATTERNS:
            if pattern.search(parsed.path):
                return True
        return False
    
    def extract_metadata(self, parsed: ParsedURL) -> Optional[Dict[str, Any]]:
        """Extract WebSocket type."""
        path_lower = parsed.path.lower()
        
        ws_type = "generic"
        if "socket.io" in path_lower:
            ws_type = "socket.io"
        elif "sockjs" in path_lower:
            ws_type = "sockjs"
        elif "signalr" in path_lower:
            ws_type = "signalr"
        elif "graphql-ws" in path_lower:
            ws_type = "graphql-ws"
        elif "/cable" in path_lower:
            ws_type = "actioncable"
        
        return {"ws_type": ws_type}
