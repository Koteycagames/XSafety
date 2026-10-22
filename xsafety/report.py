"""HTML-отчёт по одной проверке.

Отчёт самодостаточен: без внешних CSS/JS/картинок, чтобы открываться
офлайн и не тянуть сторонние ресурсы. Все значения из файла
экранируются через ``html.escape`` — это единственный слой, который
формирует HTML из недоверенных данных.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from .config import MODELS_BY_ID
from .scan.types import Finding, ScanResult, Severity

VERDICT_LABEL = {
    "clean": "Чисто",
    "suspicious": "Подозрительно",
    "malicious": "Опасно",
}

VERDICT_HINT = {
    "clean": "Сигнатуры не сработали. Это не гарантирует полную безопасность — запускайте только доверенные файлы.",
    "suspicious": "Найдены подозрительные конструкции. Проверьте находки перед запуском.",
    "malicious": "Обнаружены признаки вредоносного поведения. Не запускайте файл.",
}

SEVERITY_COLOR = {
    Severity.CRITICAL: "#ff4d6d",
    Severity.HIGH: "#ff8a3d",
    Severity.MEDIUM: "#ffd166",
    Severity.LOW: "#7cc7ff",
    Severity.INFO: "#9aa7c7",
}


def _size(value: int) -> str:
    if value < 1024:
        return f"{value} Б"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} КБ"
    return f"{value / (1024 * 1024):.2f} МБ"


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _finding_card(index: int, finding) -> str:
    color = SEVERITY_COLOR.get(finding.severity, "#9aa7c7")
    entry = f'<div class="meta">Вложение: <code>{_escape(finding.entry)}</code></div>' if finding.entry else ""
    offset = f'<div class="meta">Строка: {int(finding.offset)}</div>' if finding.offset else ""
    evidence = (
        f'<pre class="evidence">{_escape(finding.evidence)}</pre>' if finding.evidence else ""
    )
    return f"""
    <article class="finding" style="--sev:{color}">
      <header>
        <span class="sev">{_escape(finding.severity.label)}</span>
        <h3>{index}. {_escape(finding.title)}</h3>
        <code class="sig">{_escape(finding.sig_id)}</code>
      </header>
      <p>{_escape(finding.description)}</p>
      {entry}{offset}
      {evidence}
    </article>"""


def result_from_dict(payload: dict[str, object]) -> ScanResult | None:
    """Восстанавливает ScanResult из JSON, сохранённого в истории.

    Любые повреждённые поля отбрасываются: отчёт не должен падать из-за
    старой записи в базе.
    """
    if not isinstance(payload, dict):
        return None
    try:
        raw_findings = payload.get("findings") or []
        findings: list[Finding] = []
        for item in raw_findings[:200]:
            if not isinstance(item, dict):
                continue
            try:
                severity = Severity(str(item.get("severity", "info")))
            except ValueError:
                severity = Severity.INFO
            offset_value = item.get("offset")
            findings.append(
                Finding(
                    sig_id=str(item.get("sig_id", "unknown"))[:64],
                    title=str(item.get("title", ""))[:160],
                    severity=severity,
                    description=str(item.get("description", ""))[:1000],
                    evidence=str(item.get("evidence", ""))[:400],
                    entry=str(item["entry"])[:240] if item.get("entry") else None,
                    offset=int(offset_value) if isinstance(offset_value, (int, float)) else None,
                )
            )
        notes = [str(note)[:240] for note in (payload.get("notes") or []) if isinstance(note, str)][:24]
        return ScanResult(
            filename=str(payload.get("filename", "file"))[:180],
            extension=str(payload.get("extension", ""))[:12],
            model=str(payload.get("model", "m1"))[:16],
            size=max(int(payload.get("size", 0) or 0), 0),
            sha256=str(payload.get("sha256", ""))[:64],
            verdict=str(payload.get("verdict", "suspicious"))[:16],
            findings=findings,
            scanned_entries=max(int(payload.get("scanned_entries", 1) or 1), 1),
            analyzed_bytes=max(int(payload.get("analyzed_bytes", 0) or 0), 0),
            elapsed_ms=max(int(payload.get("elapsed_ms", 0) or 0), 0),
            notes=notes,
        )
    except (TypeError, ValueError):
        return None


def build_html_report(result: ScanResult, plan_name: str = "", generated_at: datetime | None = None) -> str:
    model = MODELS_BY_ID.get(result.model)
    model_name = model.name if model else result.model
    verdict = result.verdict if result.verdict in VERDICT_LABEL else "suspicious"
    stamp = (generated_at or datetime.now(timezone.utc)).strftime("%d.%m.%Y %H:%M UTC")
    counts = {severity: 0 for severity in Severity}
    for finding in result.findings:
        counts[finding.severity] += 1

    chips = "".join(
        f'<span class="chip" style="--sev:{SEVERITY_COLOR[sev]}">{_escape(sev.label)}: {counts[sev]}</span>'
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
        if counts[sev]
    )
    findings_html = "".join(_finding_card(i, f) for i, f in enumerate(result.findings, 1))
    if not findings_html:
        findings_html = '<p class="empty">Сигнатуры не сработали.</p>'
    notes_html = "".join(f"<li>{_escape(note)}</li>" for note in result.notes)
    notes_block = f'<section class="notes"><h2>Примечания</h2><ul>{notes_html}</ul></section>' if notes_html else ""
    plan_line = f'<div class="meta">Тариф: {_escape(plan_name)}</div>' if plan_name else ""

    return f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>XSafety — отчёт: {_escape(result.filename)}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 32px 16px; background: #080c18; color: #e8eefc;
    font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
  }}
  .wrap {{ max-width: 920px; margin: 0 auto; }}
  .brand {{ display:flex; align-items:center; gap:10px; color:#8ea2c8; font-size:13px; letter-spacing:.12em; text-transform:uppercase; }}
  .brand b {{ color:#e8eefc; letter-spacing:.02em; text-transform:none; font-size:16px; }}
  .card {{ background:#0e1426; border:1px solid #1e2942; border-radius:16px; padding:24px; margin-top:16px; }}
  .verdict {{ border-left:4px solid var(--v); }}
  .verdict h1 {{ margin:0 0 4px; font-size:22px; color:var(--v); }}
  .verdict p {{ margin:6px 0 0; color:#aebbd8; }}
  .file {{ font-size:18px; font-weight:650; word-break:break-all; }}
  .meta {{ color:#8ea2c8; font-size:13px; margin-top:4px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin-top:18px; }}
  .stat {{ background:#111a2f; border:1px solid #1e2942; border-radius:12px; padding:12px 14px; }}
  .stat span {{ display:block; color:#8ea2c8; font-size:12px; text-transform:uppercase; letter-spacing:.08em; }}
  .stat b {{ font-size:15px; word-break:break-all; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12.5px; color:#bcd0ff; }}
  .chip {{ display:inline-block; margin:12px 8px 0 0; padding:5px 10px; border-radius:999px;
          border:1px solid color-mix(in srgb, var(--sev) 45%, transparent); color:var(--sev); font-size:12.5px; }}
  h2 {{ font-size:15px; letter-spacing:.06em; text-transform:uppercase; color:#8ea2c8; margin:0 0 12px; }}
  .finding {{ background:#0b1222; border:1px solid #1e2942; border-left:3px solid var(--sev); border-radius:12px; padding:16px; margin-top:12px; }}
  .finding header {{ display:flex; flex-wrap:wrap; align-items:center; gap:10px; }}
  .finding h3 {{ margin:0; font-size:15.5px; }}
  .sev {{ color:var(--sev); border:1px solid color-mix(in srgb, var(--sev) 40%, transparent); border-radius:6px;
          padding:2px 7px; font-size:11.5px; text-transform:uppercase; letter-spacing:.06em; }}
  .sig {{ margin-left:auto; color:#7f8db0; }}
  .finding p {{ margin:10px 0 0; color:#c7d3ec; }}
  .evidence {{ margin:10px 0 0; padding:10px 12px; background:#080d19; border:1px solid #1a2438; border-radius:8px;
               white-space:pre-wrap; word-break:break-word; color:#9fb4dd; }}
  .empty {{ color:#8ea2c8; }}
  .notes ul {{ margin:0; padding-left:20px; color:#c7d3ec; }}
  footer {{ margin-top:18px; color:#6f7d9e; font-size:12px; text-align:center; }}
  @media print {{
    body {{ background:#fff; color:#111; }}
    .card, .finding, .stat {{ background:#fff; border-color:#ddd; }}
    .finding p, .notes ul {{ color:#222; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <div class="brand">🛡 <b>XSafety</b> · отчёт о проверке</div>

  <section class="card verdict" style="--v:{SEVERITY_COLOR.get(result.worst, '#9aa7c7')}">
    <h1>{_escape(VERDICT_LABEL[verdict])}</h1>
    <div class="file">{_escape(result.filename)}</div>
    <div class="meta">Модель: {_escape(model_name)} · {stamp}</div>
    <p>{_escape(VERDICT_HINT[verdict])}</p>
    <div>{chips}</div>
  </section>

  <section class="card">
    <h2>Параметры</h2>
    <div class="grid">
      <div class="stat"><span>Размер</span><b>{_escape(_size(result.size))}</b></div>
      <div class="stat"><span>Расширение</span><b>.{_escape(result.extension)}</b></div>
      <div class="stat"><span>Файлов проверено</span><b>{int(result.scanned_entries)}</b></div>
      <div class="stat"><span>Время</span><b>{int(result.elapsed_ms)} мс</b></div>
    </div>
    <div class="meta" style="margin-top:14px">SHA-256: <code>{_escape(result.sha256)}</code></div>
    {plan_line}
  </section>

  <section class="card">
    <h2>Находки — {len(result.findings)}</h2>
    {findings_html}
  </section>

  {notes_block}

  <footer>XSafety · отчёт сформирован локально · не запускайте подозрительные файлы</footer>
</div>
</body>
</html>"""


__all__ = ["build_html_report", "result_from_dict", "VERDICT_LABEL"]
