# Argus — TODO

## Critical (блокируют реальное использование)

- [x] **P1: Wire new tools into orchestrator** — httpx, katana, gau, dnsx, tlsx, ffuf должны вызываться в `_run_recon` и `_run_analysis`
- [x] **P2: Preset-driven tool selection** — quick/full/recon/web должны запускать разный набор инструментов
- [x] **P3: Rich progress display** — live-обновление текущего инструмента, прогресс по этапам
- [x] **P4: Reports show new tool data** — HTTP probes, crawl results, historical URLs, fuzz results, TLS certs в HTML/MD/JSON

## Important (улучшают качество)

- [x] **P5: OSINT API integrations** — Shodan, VirusTotal, SecurityTrails
- [x] **P6: Resume interrupted scans** — `argus scan --resume <scan-id>` из partial results
- [x] **P7: Nuclei custom templates** — `argus scan --templates /path/to/templates/`
- [x] **P8: Concurrent subtasks** — asyncio.gather для параллельных инструментов (3-5x ускорение)

## Nice to Have

- [ ] **P9: Screenshot capture** — gowitness/aquatone интеграция для скриншотов
- [x] **P10: CI/CD SARIF output** — `argus scan --output sarif` для GitHub Security
- [x] **P11: Incremental scanning** — diff engine (new/resolved/unchanged findings)
- [x] **P12: Web dashboard** — `argus dashboard` — Flask UI (dark theme)
