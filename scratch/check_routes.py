import sys, os
sys.path.insert(0, os.getcwd())
from app.main import create_app
app = create_app()
for r in app.routes:
    if hasattr(r, 'path') and 'command' in r.path:
        print(r.path, r.endpoint.__module__)
