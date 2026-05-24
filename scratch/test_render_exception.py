# scratch/test_render_exception.py
import sys
from pathlib import Path
from fastapi.templating import Jinja2Templates

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.config import Settings
from app.main import init_templates

settings = Settings()
templates = init_templates(settings)

class MockRequest:
    def __init__(self):
        self.url = type('URL', (), {'path': '/targets/myseek.xyz/ai/command'})()
        self.query_params = {}
        self.state = type('State', (), {'settings': settings})()

try:
    print("Attempting to render app/templates/ai/command.html...")
    t = templates.get_template("ai/command.html")
    res = t.render({"request": MockRequest(), "scope": "myseek.xyz", "threads": [], "thread_id": None, "messages": []})
    print("✅ RENDER SUCCESS for ai/command.html!")
except Exception as e:
    print("❌ RENDER FAILED for ai/command.html!")
    import traceback
    traceback.print_exc()
