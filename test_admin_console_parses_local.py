"""The self-host console is ONE inline <script>. If it does not parse, the whole
page is dead: the shell renders, navigation never appears, "Loading..." stays
forever, and nothing anywhere tells the operator why.

⚠⚠ WHY THIS EXISTS. `ec8bba8` (05.09.2026) wrote a JS escape as \\' inside the
non-raw triple-quoted literal that holds the page. Python ate the backslash, the
browser got a bare quote, the string closed early, and every island running that
build served a dead console. The flagship and is2 both sat like that for three
days until the founder opened one (08.09). Nothing failed: the page is 200, the
HTML is complete, and the only symptom is a word that never changes.

Two guards, because they fail in different places:

 * the whole script is handed to a real JavaScript parser (node --check). This
   is the one that would have caught it. It skips where node is missing rather
   than failing: it is a developer guard, not a runtime dependency.
 * the source is scanned for the exact footgun, so the next person to write an
   escaped quote in an inline handler is told what to write instead, even on a
   machine with no node.
"""

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from app.admin_console import ADMIN_CONSOLE_HTML

ok = bad = 0


def check(label: str, cond: bool, detail: str = "") -> None:
    global ok, bad
    if cond:
        ok += 1
        print(f"  ok   {label}")
    else:
        bad += 1
        print(f"  FAIL {label}" + (f" -- {detail}" if detail else ""))


blocks = re.findall(r"<script[^>]*>(.*?)</script>", ADMIN_CONSOLE_HTML, re.S)
check("the console carries its client inline", len(blocks) >= 1, f"{len(blocks)} blocks")

if shutil.which("node") is None:
    print("  skip node --check (node not installed)")
else:
    for i, block in enumerate(blocks):
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
            fh.write(block)
            path = fh.name
        try:
            proc = subprocess.run(["node", "--check", path], capture_output=True, text=True)
        finally:
            Path(path).unlink(missing_ok=True)
        check(
            f"script block {i} parses as JavaScript",
            proc.returncode == 0,
            proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "",
        )

# The specific footgun, named so the next edit does not repeat it: inside the
# triple-quoted literal a JS \' must be written \\'. A bare \' is a Python
# escape that vanishes, and what reaches the browser is an unterminated string.
source = Path(__file__).with_name("app") / "admin_console.py"
text = source.read_text(encoding="utf-8")
offenders = [m.start() for m in re.finditer(r"(?<!\\)\\'", text)]
check(
    "no bare \\' in the console source (write \\\\' so the browser gets an escaped quote)",
    not offenders,
    f"offsets {offenders}",
)

print(f"\nadmin console parses: {ok}/{ok + bad} ok")
raise SystemExit(0 if bad == 0 else 1)
