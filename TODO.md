# Argus — TODO

## Critical (блокируют реальное использование)

- [x] **P1: Wire new tools into orchestrator** — httpx, katana, gau, dnsx, tlsx, ffuf должны вызываться в `_run_recon` и `_run_analysis`
- [x] **P2: Preset-driven tool selection** — quick/full/recon/web должны запускать разный набор инструментов
- [x] **P3: Rich progress display** — live-обновление текущего инструмента, прогресс по этапам
- [x] **P4: Reports show new tool data** — HTTP probes, crawl results, historical URLs, fuzz results, TLS certs в HTML/MD/JSON

## Important (улучшают качество)

- [ ] **P5: OSINT API integrations** — Shodan, VirusTotal, SecurityTrails (ключи уже в конфиге)
- [ ] **P6: Resume interrupted scans** — `argus scan --resume <scan-id>` из partial results
- [ ] **P7: Nuclei custom templates** — поддержка пользовательских шаблонов из `~/.argus-lite/templates/`
- [ ] **P8: Concurrent subtasks** — asyncio.gather для независимых инструментов внутри одного этапа

## Nice to Have

- [ ] **P9: Screenshot capture** — gowitness/aquatone интеграция для скриншотов веб-страниц
- [ ] **P10: CI/CD SARIF output** — для интеграции с GitHub Security
- [ ] **P11: Incremental scanning** — повторный скан обрабатывает только новые находки
- [ ] **P12: Web dashboard** — локальный веб-интерфейс для просмотра результатов
