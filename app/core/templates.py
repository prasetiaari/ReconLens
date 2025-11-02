import os
from fastapi import Request
from fastapi.templating import Jinja2Templates
from jinja2.bccache import FileSystemBytecodeCache
from app.core.utils import filters

def get_templates(request: Request) -> Jinja2Templates:
    return request.app.state.templates

def init_templates(templates_dir: str) -> Jinja2Templates:
    """Initialize Jinja2Templates with bytecode cache and custom filters."""
    templates = Jinja2Templates(directory=templates_dir)

    # Set up cache directory for compiled templates
    cache_dir = os.path.join(os.getcwd(), ".jinja_cache")
    os.makedirs(cache_dir, exist_ok=True)
    templates.env.bytecode_cache = FileSystemBytecodeCache(directory=cache_dir)

    # Register custom filters
    templates.env.filters["humansize"] = filters.humansize
    templates.env.filters["timeago"] = filters.timeago

    return templates