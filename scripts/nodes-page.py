#!/usr/bin/env python3
"""Страница со списком нод сети CORE для GitHub Pages.

    nodes-page.py <nodes.json> <index.html> [commit]

`nodes.json` (его собирает workflow `deploy`) лежит рядом со страницей — его читают приложение
и ноды с `GIT_NODES=1`. Страница — для людей: адреса, регион, доступность, копирование адреса.
"""

import datetime
import html
import json
import sys

FLAGS = {"RU": "🇷🇺", "NL": "🇳🇱", "DE": "🇩🇪", "FI": "🇫🇮", "VN": "🇻🇳", "US": "🇺🇸", "FR": "🇫🇷", "GB": "🇬🇧"}


def flag(region: str) -> str:
    region = (region or "").upper()
    if region in FLAGS:
        return FLAGS[region]
    if len(region) == 2 and region.isalpha():
        return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in region)
    return "🌐"


def main() -> None:
    src, out = sys.argv[1], sys.argv[2]
    commit = sys.argv[3][:7] if len(sys.argv) > 3 else ""
    with open(src, encoding="utf-8") as f:
        nodes = json.load(f)
    online = sum(1 for n in nodes if n.get("online", True))
    updated = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rows = []
    for n in nodes:
        address = html.escape(n.get("address", ""))
        name = html.escape(n.get("name", ""))
        region = html.escape(n.get("region", ""))
        up = n.get("online", True)
        rows.append(f"""
      <li class="node">
        <div class="head">
          <span class="flag">{flag(n.get("region", ""))}</span>
          <span class="name">{name}</span>
          <span class="region">{region}</span>
          <span class="status {'up' if up else 'down'}">{'в сети' if up else 'недоступна'}</span>
        </div>
        <div class="addr">
          <code>{address}</code>
          <button type="button" data-copy="{address}">Копировать</button>
        </div>
      </li>""")

    page = f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ноды CORE</title>
<style>
  :root {{
    --bg: #f6f7fb; --card: #ffffff; --ink: #15171c; --muted: #646a78; --line: #e3e6ee;
    --accent: #3b6cf3; --up: #1f9d55; --down: #d64545;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg: #101116; --card: #191b22; --ink: #eceef3; --muted: #9aa0ad; --line: #2a2d37;
             --accent: #7b9bff; --up: #46c37b; --down: #ff6b6b; }}
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--bg); color: var(--ink);
         font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  main {{ max-width: 760px; margin: 0 auto; padding: 40px 16px 64px; }}
  h1 {{ margin: 0 0 4px; font-size: 28px; }}
  .sub {{ color: var(--muted); margin: 0 0 24px; }}
  .stats {{ display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }}
  .stat {{ background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 10px 16px; }}
  .stat b {{ font-size: 22px; display: block; }}
  .stat span {{ color: var(--muted); font-size: 13px; }}
  ul {{ list-style: none; padding: 0; margin: 0; display: grid; gap: 10px; }}
  .node {{ background: var(--card); border: 1px solid var(--line); border-radius: 16px; padding: 14px 16px; }}
  .head {{ display: flex; align-items: center; gap: 8px; }}
  .flag {{ font-size: 20px; }}
  .name {{ font-weight: 600; }}
  .region {{ color: var(--muted); font-size: 13px; }}
  .status {{ margin-left: auto; font-size: 13px; font-weight: 600; }}
  .status::before {{ content: "●"; margin-right: 5px; }}
  .up {{ color: var(--up); }} .down {{ color: var(--down); }}
  .addr {{ display: flex; gap: 8px; align-items: center; margin-top: 8px; }}
  code {{ flex: 1; min-width: 0; overflow-wrap: anywhere; font-size: 12px; color: var(--muted);
          background: var(--bg); border-radius: 8px; padding: 6px 8px; }}
  button {{ border: 0; border-radius: 999px; padding: 6px 12px; background: var(--accent); color: #fff;
            font: inherit; font-size: 13px; cursor: pointer; flex: none; }}
  footer {{ color: var(--muted); font-size: 13px; margin-top: 28px; }}
  a {{ color: var(--accent); }}
</style>
</head>
<body>
<main>
  <h1>Ноды CORE</h1>
  <p class="sub">Публичные ноды сети. Приложение само выбирает ближайшую, новая нода с <code>GIT_NODES=1</code> — соседей.</p>
  <div class="stats">
    <div class="stat"><b>{len(nodes)}</b><span>нод в списке</span></div>
    <div class="stat"><b>{online}</b><span>в сети при развёртывании</span></div>
  </div>
  <ul>{''.join(rows)}
  </ul>
  <footer>
    Машиночитаемый список: <a href="nodes.json">nodes.json</a> · обновлено {updated}{f' · {commit}' if commit else ''}
  </footer>
</main>
<script>
  document.querySelectorAll("button[data-copy]").forEach(b => b.addEventListener("click", async () => {{
    try {{ await navigator.clipboard.writeText(b.dataset.copy); b.textContent = "Скопировано"; }}
    catch (e) {{ b.textContent = "Не вышло"; }}
    setTimeout(() => b.textContent = "Копировать", 1500);
  }}));
</script>
</body>
</html>
"""
    with open(out, "w", encoding="utf-8") as f:
        f.write(page)


if __name__ == "__main__":
    main()
