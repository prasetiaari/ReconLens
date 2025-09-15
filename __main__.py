# ReconLens/__main__.py  (NEW ENGINE - rules-based + subdomain merge)
from __future__ import annotations
import argparse
import gzip
import re
import fnmatch
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qsl

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # type: ignore

try:
    from tqdm import tqdm  # type: ignore
except Exception:
    tqdm = None  # type: ignore


# =========================
# Defaults (used if --config not provided)
# =========================
DEFAULT_CONFIG: Dict[str, Any] = {
    "global": {
        "include_external": False,          # only URLs whose host is in-scope (root or subdomain)
        "allow_subdomains": [],             # optional glob allow-list, e.g. ["api.*", "dev.*"]
        "deny_subdomains": [],              # optional glob block-list
        "dedup_case_insensitive": True,     # lowercase before dedup
    },
    "categories": {
        "auth_login": {
            "enabled": True,
            "host_regex": [],
            "path_regex": [r"/(login|signin|auth|oauth|sso)(/|$)"],
            "query_keys": ["redirect_uri", "client_id", "return", "next"],
        },
        "admin_panel": {
            "enabled": True,
            "path_regex": [r"/(admin|administrator|dashboard|cpanel|manage|wp-admin|cms)(/|$)"],
        },
        "api": {
            "enabled": True,
            "host_startswith": ["api."],
            "path_regex": [r"^/api/", r"/graphql", r"/v[0-9]+/", r"/rest/"],
        },
        "upload": {
            "enabled": True,
            "path_regex": [r"/(upload|import|fileupload|media/upload)(/|$)"],
        },
        "download_dump": {
            "enabled": True,
            "path_regex": [r"/(download|export|backup|dump|database)(/|$)"],
        },
        "debug_dev": {
            "enabled": True,
            "host_startswith": ["dev.", "test.", "stage.", "staging.", "beta."],
            "path_regex": [r"/(dev|staging|test|beta|sandbox)(/|$)"],
        },
        "docs_swagger": {
            "enabled": True,
            "path_regex": [r"/(swagger|redoc|api-docs|openapi)(/|$)"],
        },
        "config_backup_source": {
            "enabled": True,
            "path_regex": [r"/\.git/", r"config\.(php|ya?ml|json)(\.(bak|old))?$"],
        },
        "sensitive_functionality": {
            "enabled": True,
            "path_regex": [
                r"/(reset|forgot)-password",
                r"/change-(email|password)",
                r"/(2fa|verify|otp|token)(/|$)",
            ],
        },
        "monitoring": {
            "enabled": True,
            "path_regex": [r"/(grafana|prometheus|metrics|zabbix|kibana|jaeger|debug)(/|$)"],
        },
        "payments": {
            "enabled": True,
            "path_regex": [r"/(checkout|payment|pay|invoice|billing|cart)(/|$)"],
        },
        "static_assets": {
            "enabled": True,
            "path_regex": [r"^/(js|css|img|images|static|assets)/"],
            "extensions": [".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2"],
        },
        "file_disclosure": {
            "enabled": True,
            "extensions": [
                ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv",
                ".zip", ".gz", ".tar", ".rar", ".7z",
                ".sql", ".sqlite", ".bak", ".log",
            ],
        },
        # NOTE: "other" is implicit; engine will always create it as fallback.
    },
}


# =========================
# CLI
# =========================
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Classify URLs into security-focused categories (new engine).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--scope", required=True, help="Root domain, e.g. example.com")
    p.add_argument("--input", required=True, help="Input URLs file (.txt or .gz)")
    p.add_argument("--out", required=True, help="Output directory for this scope")
    p.add_argument("--config", default="", help="YAML config (if provided, FULLY replaces defaults)")
    return p.parse_args()


# =========================
# Helpers
# =========================
def load_config(path: str) -> Dict[str, Any]:
    """Load YAML config; if not provided, return DEFAULT_CONFIG. FULL replace semantics."""
    if not path:
        return DEFAULT_CONFIG
    if yaml is None:
        raise RuntimeError("PyYAML not installed but --config provided")
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data  # FULL replace


def iter_lines(path: str) -> Iterable[str]:
    p = Path(path)
    if p.suffix == ".gz":
        with gzip.open(p, "rt", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                yield ln.strip()
    else:
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                yield ln.strip()


def in_scope(host: str, scope: str) -> bool:
    if not host:
        return False
    host = host.lower()
    scope = scope.lower().lstrip(".")
    return host == scope or host.endswith("." + scope)


def glob_ok(host: str, globs: List[str]) -> bool:
    if not globs:
        return True
    return any(fnmatch.fnmatch(host, g) for g in globs)


def glob_block(host: str, globs: List[str]) -> bool:
    if not globs:
        return False
    return any(fnmatch.fnmatch(host, g) for g in globs)


def get_ext(path: str) -> str:
    path = path.split("?")[0]
    idx = path.rfind(".")
    if idx == -1:
        return ""
    return path[idx:].lower()


def compile_patterns(lst: Optional[List[str]]) -> List[re.Pattern]:
    if not lst:
        return []
    return [re.compile(x, re.IGNORECASE) for x in lst]


# =========================
# Rule building
# =========================
class Rule:
    __slots__ = ("name", "host_starts", "host_re", "path_re", "qkeys", "exts", "enabled")

    def __init__(
        self,
        name: str,
        host_starts: List[str] | None,
        host_re: List[re.Pattern] | None,
        path_re: List[re.Pattern] | None,
        qkeys: Set[str] | None,
        exts: Set[str] | None,
        enabled: bool = True,
    ):
        self.name = name
        self.host_starts = host_starts or []
        self.host_re = host_re or []
        self.path_re = path_re or []
        self.qkeys = qkeys or set()
        self.exts = exts or set()
        self.enabled = enabled

    def match(self, host: str, path: str, query_keys: Set[str]) -> bool:
        if not self.enabled:
            return False

        if self.host_starts and not any(host.lower().startswith(hs.lower()) for hs in self.host_starts):
            return False

        if self.host_re and not any(rx.search(host) for rx in self.host_re):
            return False

        if self.path_re and not any(rx.search(path) for rx in self.path_re):
            return False

        if self.qkeys and not (self.qkeys & query_keys):
            return False

        if self.exts:
            ext = get_ext(path)
            if ext not in self.exts:
                return False

        return True


def build_rules(cfg: Dict[str, Any]) -> Tuple[Dict[str, Rule], Dict[str, Any]]:
    cats = cfg.get("categories", {}) or {}
    rules: Dict[str, Rule] = {}
    for name, spec in cats.items():
        if not isinstance(spec, dict):
            continue
        enabled = bool(spec.get("enabled", True))
        host_starts = list(spec.get("host_startswith", []) or [])
        host_re = compile_patterns(spec.get("host_regex"))
        path_re = compile_patterns(spec.get("path_regex"))
        qkeys = set(k.lower() for k in (spec.get("query_keys") or []))
        exts = set(x.lower() for x in (spec.get("extensions") or []))
        rules[name] = Rule(
            name=name,
            host_starts=host_starts,
            host_re=host_re,
            path_re=path_re,
            qkeys=qkeys,
            exts=exts,
            enabled=enabled,
        )
    return rules, (cfg.get("global", {}) or {})


# =========================
# Classifier
# =========================
def classify_url(url: str, rules: Dict[str, Rule]) -> List[str]:
    try:
        p = urlparse(url)
    except Exception:
        return []
    host = (p.netloc or "").lower()
    path = p.path or "/"
    qkeys = set(k.lower() for k, _ in parse_qsl(p.query, keep_blank_values=True))

    matched: List[str] = []
    for name, rule in rules.items():
        if rule.match(host, path, qkeys):
            matched.append(name)
    return matched


# =========================
# Main
# =========================
def main() -> None:
    args = parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    cfg = load_config(args.config)
    rules, gopt = build_rules(cfg)

    include_external = bool(gopt.get("include_external", False))
    allow_globs = list(gopt.get("allow_subdomains") or [])
    deny_globs = list(gopt.get("deny_subdomains") or [])
    ci_dedup = bool(gopt.get("dedup_case_insensitive", True))

    # buffers per category (+ fallback 'other')
    buffers: Dict[str, Set[str]] = {name: set() for name in rules.keys() if rules[name].enabled}
    buffers["other"] = set()

    # kumpulkan subdomain unik dari seluruh URL (in-scope)
    subdomains_set: Set[str] = set()

    total_in = 0

    itr: Iterable[str] = iter_lines(args.input)
    if tqdm:
        itr = tqdm(itr, desc="Classifying", unit="url")

    for raw in itr:
        if not raw:
            continue
        total_in += 1
        url = raw.strip()

        # parse untuk host
        try:
            p = urlparse(url)
            host = (p.netloc or "").split("@")[-1].split(":")[0].lower()  # buang auth & port
        except Exception:
            continue

        # scope filter
        if not include_external and not in_scope(host, args.scope):
            continue
        if deny_globs and glob_block(host, deny_globs):
            continue
        if allow_globs and not glob_ok(host, allow_globs):
            if not any(fnmatch.fnmatch(host, g) for g in allow_globs) and not in_scope(host, args.scope):
                continue

        # kumpulkan subdomain in-scope
        if in_scope(host, args.scope):
            subdomains_set.add(host)

        # klasifikasi kategori
        cats = classify_url(url, rules)
        val = url.lower() if ci_dedup else url

        if cats:
            for c in cats:
                if c in buffers:
                    buffers[c].add(val)
        else:
            buffers["other"].add(val)

    # ---- write category outputs ----
    results: List[Tuple[str, int]] = []
    for cat, items in buffers.items():
        out_path = out_dir / f"{cat}.txt"
        data = sorted(items)
        with out_path.open("w", encoding="utf-8") as f:
            f.write("\n".join(data) + ("\n" if data else ""))
        results.append((cat, len(data)))

    # ---- merge & write subdomains.txt ----
    subs_path = out_dir / "subdomains.txt"
    existing: Set[str] = set()
    if subs_path.exists():
        try:
            with subs_path.open("r", encoding="utf-8", errors="ignore") as f:
                for ln in f:
                    h = ln.strip().lower()
                    if h:
                        existing.add(h)
        except Exception:
            pass
    merged_subs = sorted(existing | subdomains_set)
    with subs_path.open("w", encoding="utf-8") as f:
        f.write("\n".join(merged_subs) + ("\n" if merged_subs else ""))
    results.append(("subdomains", len(merged_subs)))

    # ---- summary table ----
    name_w = max([len("Category")] + [len(n) for n, _ in results]) if results else 8
    cnt_w = max([len("Written")] + [len(str(c)) for _, c in results]) if results else 7
    line = f"+{'-'*(name_w+2)}+{'-'*(cnt_w+2)}+"

    print()
    print(line)
    print(f"| {'Category'.ljust(name_w)} | {'Written'.rjust(cnt_w)} |")
    print(line)
    for n, c in sorted(results):
        print(f"| {n.ljust(name_w)} | {str(c).rjust(cnt_w)} |")
    print(line)
    print(f"Processed: {total_in} URLs")
    print(f"Outputs in: {out_dir.resolve()}")


if __name__ == "__main__":
    main()
