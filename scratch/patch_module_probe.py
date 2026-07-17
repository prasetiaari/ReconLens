import sys
from pathlib import Path

f = Path("app/templates/components/_module_probe_modal.html")
content = f.read_text()

# 1. Update HTML elements in the {% else %} block
old_html = """        {% else %}
          <div class="text-slate-500 text-sm">No extra options for this module.</div>
        {% endif %}"""

new_html = """        {% else %}
          <div class="space-y-2 mt-4 pt-2 border-t">
            <div class="text-slate-700 font-medium">Probe Mode</div>
            <label class="flex items-center gap-2">
              <input type="radio" name="{{ modal_id }}_probe_mode" value="HEAD" checked class="accent-rose-600">
              <span><strong>Fast Screening</strong> (HEAD only)</span>
            </label>
            <label class="flex items-center gap-2">
              <input type="radio" name="{{ modal_id }}_probe_mode" value="GET" class="accent-rose-600">
              <span><strong>Content Probe</strong> (GET title & body size)</span>
            </label>
            <label class="flex items-center gap-2">
              <input type="radio" name="{{ modal_id }}_probe_mode" value="OPTIONS" class="accent-rose-600">
              <span><strong>Method Discovery</strong> (OPTIONS for allowed methods)</span>
            </label>
          </div>

          <label class="flex items-start gap-2 mt-2">
            <input id="{{ modal_id }}_only_alive" type="checkbox" checked class="mt-1 accent-rose-600">
            <span class="text-slate-600 text-sm"><strong>Only probe alive endpoints</strong> (skip dead endpoints)</span>
          </label>
        {% endif %}"""

content = content.replace(old_html, new_html)

# 2. Update JS payload
old_js = """      if (moduleVal=="dirsearch")
           path = `/targets/${encodeURIComponent(scopeVal)}/collect/${encodeURIComponent(moduleVal)}?`;
      else
           path = `/targets/${encodeURIComponent(scopeVal)}/probe/module/${encodeURIComponent(moduleVal)}`;
      let url = path;"""

new_js = """      let url = "";
      if (moduleVal=="dirsearch") {
           url = `/targets/${encodeURIComponent(scopeVal)}/collect/${encodeURIComponent(moduleVal)}?`;
      } else if (moduleVal=="probe_paths") {
           url = `/targets/${encodeURIComponent(scopeVal)}/collect/${encodeURIComponent(moduleVal)}?`;
      } else {
           const modeChoice = document.querySelector(`input[name="${modal_id}_probe_mode"]:checked`)?.value || 'HEAD';
           const onlyAlive = document.getElementById(`${modal_id}_only_alive`)?.checked ? 'true' : 'false';
           url = `/targets/${encodeURIComponent(scopeVal)}/probe/module/${encodeURIComponent(moduleVal)}?mode=${modeChoice}&only_alive=${onlyAlive}`;
      }"""

content = content.replace(old_js, new_js)

f.write_text(content)
print("module_probe_modal.html patched successfully")
