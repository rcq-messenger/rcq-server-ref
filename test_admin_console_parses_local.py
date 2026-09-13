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

The page speaks three languages, and that adds a second way to ship something
broken that still returns 200: an id that no table has. At runtime t() falls
back to English and, failing that, renders the id in brackets and warns, so a
missing string is visible rather than silent - but nobody reads the console of
an admin page they are not debugging. So the ids are checked here too: every id
the page asks for must exist somewhere, and no translation may carry an id the
page never asks for (that one is a typo whose only symptom is an English word
where a translated one was meant). Untranslated ids are COUNTED, not failed:
adding an English string without its Russian is allowed, it renders in English,
and the number here says how many are waiting.
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

# ---- string ids -----------------------------------------------------------
#
# English lives in two places on purpose and is read from both: the markup
# (data-i18n / data-i18n-ph / data-i18n-title, which the page captures into
# EN_BASE at boot) and the EN table for the strings the script builds itself.
# The ru/zh tables are overlays keyed by the same ids.
def dict_keys(tag: str) -> set[str]:
    """The keys of one dictionary, read between its sentinel comments."""
    block = re.search(rf"/\* i18n:{tag} \*/(.*?)/\* /i18n:{tag} \*/", text, re.S)
    if block is None:
        return set()
    return set(re.findall(r"^\s*'([A-Za-z0-9_.]+)':", block.group(1), re.M))


markup_ids = set(re.findall(r'data-i18n(?:-ph|-title)?="([A-Za-z0-9_.]+)"', text))
en_ids = dict_keys("EN") | markup_ids
ru_ids, zh_ids = dict_keys("RU"), dict_keys("ZH")
# Every id the script asks for by name. `set.<key>` is the one family that is
# allowed to be absent from English: those labels come from the island itself
# and tOpt() falls back to what it sent (see the console's own comment).
asked = set(re.findall(r"\bt\('([A-Za-z0-9_.]+)'", text))

check("the console defines English strings", len(en_ids) > 100, f"{len(en_ids)} ids")
missing_en = sorted(asked - en_ids)
check("every id the page asks for has English", not missing_en, f"{missing_en}")
for tag, ids in (("ru", ru_ids), ("zh", zh_ids)):
    dead = sorted(k for k in ids - en_ids if not k.startswith("set."))
    check(f"no {tag} string for an id the page never asks for", not dead, f"{dead}")

# A translation that drops a {placeholder} does not fail anywhere: it renders,
# and the number, the name or the link it was supposed to carry is simply not in
# the sentence. Compare the sets instead.
def placeholders(block_text: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for key, value in re.findall(r"^\s*'([A-Za-z0-9_.]+)':\s*(.*?),\s*$", block_text, re.M):
        out[key] = set(re.findall(r"[{]([a-z0-9_]+)[}]", value))
    return out


def block_text(tag: str) -> str:
    m = re.search(rf"/\* i18n:{tag} \*/(.*?)/\* /i18n:{tag} \*/", text, re.S)
    return m.group(1) if m else ""


en_ph = placeholders(block_text("EN"))
for tag in ("RU", "ZH"):
    other = placeholders(block_text(tag))
    wrong = sorted(k for k, v in other.items() if k in en_ph and v != en_ph[k])
    check(f"{tag.lower()} keeps every placeholder English has", not wrong, f"{wrong}")

for tag, ids in (("ru", ru_ids), ("zh", zh_ids)):
    todo = sorted(en_ids - ids)
    print(f"  note {tag}: {len(ids)} strings, {len(todo)} id(s) still English"
          + (f" -- {todo[:8]}" if todo else ""))

print(f"\nadmin console parses: {ok}/{ok + bad} ok")
raise SystemExit(0 if bad == 0 else 1)
