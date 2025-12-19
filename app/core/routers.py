import importlib
import pkgutil
from fastapi import FastAPI

def load_all_routers(app: FastAPI, base_pkg: str = "app.routers"):
    """
    Dynamically import all routers from app.routers and register them.
    Only includes modules that define 'router' or 'router' in submodules.
    """
    package = importlib.import_module(base_pkg)
    for _, name, ispkg in pkgutil.walk_packages(package.__path__, base_pkg + "."):
        # Skip api_v2 - it's manually included in main.py with proper prefix
        if "api_v2" in name:
            continue
        try:
            mod = importlib.import_module(name)
            router = getattr(mod, "router", None)
            if router:
                app.include_router(router)
        except Exception as e:
            print(f"[WARN] skipping {name}: {e}")