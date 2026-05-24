# scratch/test_imports.py
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    print("Testing app.services.ai_rulegen import...")
    import app.services.ai_rulegen as rulegen
    print("✅ app.services.ai_rulegen successfully imported!")

    print("Testing parse_prompt_to_plan_or_chat function call...")
    res = rulegen.parse_prompt_to_plan_or_chat(prompt="Jalankan dirsearch", scope="myseek.xyz")
    print("✅ parse_prompt_to_plan_or_chat output:")
    print(res)

    print("Testing app.routers.ai_cmd import...")
    import app.routers.ai_cmd as ai_cmd
    print("✅ app.routers.ai_cmd successfully imported!")
    
    print("ALL TESTS PASSED SUCCESSFULLY! No syntax or runtime import errors.")
except Exception as e:
    print("❌ ERROR OCCURRED during import testing:")
    import traceback
    traceback.print_exc()
    sys.exit(1)
