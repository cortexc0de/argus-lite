# 📋 Spec: Argus Lite — Локальный сканер безопасности для Kali

## 1. Назначение и границы

### 1.1 Цель
Создать **локальный CLI-инструмент** для безопасного тестирования веб-сайтов на Kali Linux, который:
- Автоматизирует ручные команды из гайда выше
- Собирает результаты в единый отчёт
- **Не выполняет эксплуатацию** (только детектирование)
- Работает полностью offline (кроме внешних API по желанию)

### 1.2 Границы (Scope)
| Включено | Исключено |
|----------|-----------|
| ✅ Пассивная разведка (DNS, whois, субдомены) | ❌ Брутфорс паролей |
| ✅ Активное сканирование портов (с лимитами) | ❌ SQL-инъекции с эксплуатацией |
| ✅ Фингерпринтинг технологий | ❌ XSS/CSRF атаки |
| ✅ Проверка security headers | ❌ DoS/DDoS тесты |
| ✅ Nuclei (только info/low шаблоны) | ❌ Обход WAF/защит |
| ✅ Генерация отчёта (JSON/Markdown) | ❌ Удалённое выполнение кода |

---

## 2. Архитектура программы

### 2.1 Высокоуровневая схема
```
┌─────────────────────────────────────────────────────────────┐
│                      CLI Interface                          │
│              (argus-lite scan <target>)                     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   Input Sanitizer                           │
│  - Strict regex валидация target                            │
│  - Защита от command injection                              │
│  - Нормализация входных данных                              │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Core Orchestrator                        │
│  - Валидация цели                                           │
│  - Проверка scope (разрешение)                              │
│  - Управление этапами сканирования                          │
│  - Обработка ошибок + graceful shutdown                     │
│  - Progress reporting (Rich)                                │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    ToolRunner (абстракция)                  │
│  - check_available() — проверка доступности инструмента     │
│  - run(args, timeout) — безопасный запуск subprocess        │
│  - parse(raw_output) — парсинг в структурированные данные   │
│  - Никогда shell=True, аргументы только списком             │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│   Recon      │   │   Analysis   │   │   Report     │
│   Package    │   │   Package    │   │   Package    │
│              │   │              │   │              │
│ • dns.py     │   │ • ports.py   │   │ • json.py    │
│ • whois.py   │   │ • headers.py │   │ • markdown.py│
│ • subs.py    │   │ • tech.py    │   │ • html.py    │
│ • certs.py   │   │ • ssl.py     │   │ • summary.py │
│              │   │ • nuclei.py  │   │              │
└──────────────┘   └──────────────┘   └──────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Storage Layer                            │
│  - ~/argus-lite/scans/<timestamp>/                         │
│  - raw/ (исходные выводы инструментов)                     │
│  - normalized/ (структурированные данные)                  │
│  - report/ (финальные отчёты)                              │
│  - partial/ (промежуточные результаты при прерывании)      │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Модель конкурентности
Инструмент использует **asyncio** как основу конкурентности (все задачи I/O-bound):
- Внешние инструменты запускаются через `asyncio.create_subprocess_exec()`
- Внутри одного этапа задачи могут выполняться параллельно (например, DNS + whois)
- Между этапами — последовательное выполнение (recon → analysis → report)
- `asyncio.Semaphore` для ограничения `concurrent_requests`
- `asyncio.wait_for()` для таймаутов на каждый инструмент

### 2.3 Graceful Shutdown
При получении SIGINT/SIGTERM:
1. Устанавливается флаг `shutdown_requested = True`
2. Текущие subprocess получают SIGTERM → ожидание 5 сек → SIGKILL
3. Собранные промежуточные результаты сохраняются в `partial/`
4. Генерируется частичный отчёт со статусом `interrupted`
5. Аудит-лог записывает событие прерывания

### 2.4 Progress Reporting
Для длительных сканирований (30-60 мин) используется Rich:
- `rich.progress.Progress` — прогресс-бар по этапам
- `rich.live.Live` — live-обновление текущего действия
- `rich.console.Console` — цветной вывод статуса каждого инструмента
- При завершении этапа — summary в консоль

---

## 3. Модули и их ответственность

### 3.1 CLI Interface
**Файл:** `cli.py`

**Команды:**
```bash
argus-lite init                    # Первоначальная настройка
argus-lite scan <target> [options] # Запуск сканирования
argus-lite report <scan-id>        # Просмотр отчёта
argus-lite list                    # Список сканирований
argus-lite config show             # Показать конфигурацию
argus-lite tools check             # Проверка доступности инструментов
```

**Параметры сканирования:**
| Флаг | Описание | Default |
|------|----------|---------|
| `--target` | Домен/IP для сканирования | (required) |
| `--preset` | quick / full / recon / web | `quick` |
| `--output` | Формат отчёта (json/md/html) | `md` |
| `--safe` | Только пассивные проверки | `false` |
| `--rate-limit` | Запросов в секунду | `10` |
| `--timeout` | Таймаут на запрос (сек) | `30` |
| `--confirm` | Требовать подтверждение цели | `true` |

**Пример:**
```bash
argus-lite scan example.com --preset full --output html --rate-limit 20
```

---

### 3.2 Core Orchestrator
**Файл:** `core/orchestrator.py`

**Ответственность:**
1. **Валидация входа (Input Sanitization):**
   - Проверка формата target (domain/IP/URL)
   - **Strict regex:** домены `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,253}[a-zA-Z0-9]$`, IP по стандарту
   - Проверка `/etc/hosts` на локальные цели
   - Требование явного подтверждения (`--confirm`)
   - **Запрет:** shell-метасимволы (`;`, `|`, `$`, `` ` ``, `&`, `>`, `<`) в target

2. **Управление этапами:**
   ```python
   stages = [
       "input_sanitization",     # ПЕРВЫМ: очистка и валидация ввода
       "scope_validation",       # Проверка allowlist/denylist
       "tool_availability",      # Проверка доступности инструментов
       "passive_recon",
       "active_recon",
       "service_detection",
       "vulnerability_scan",
       "report_generation"
   ]
   ```

3. **Классификация ошибок:**
   | Тип ошибки | Действие |
   |------------|----------|
   | Scope violation | Немедленная остановка |
   | Command injection attempt | Немедленная остановка + alert в аудит |
   | Tool not found | Пропуск этапа + warning |
   | Tool timeout | Пропуск инструмента + warning |
   | Tool crash (segfault) | Сохранение partial result + warning |
   | Network unreachable | Пропуск сетевых этапов + warning |
   | DNS resolution failed | Остановка (невалидная цель) |

4. **Аудит:**
   - Запись всех действий в `audit.log`
   - Timestamp каждого этапа
   - Сохранение команд инструментов (без секретов)

5. **Graceful Shutdown:**
   - Обработка SIGINT/SIGTERM
   - Сохранение partial results
   - Корректное завершение subprocess-ов

---

### 3.3 ToolRunner (абстракция запуска инструментов)
**Файл:** `core/tool_runner.py`

**Базовый протокол для всех обёрток внешних инструментов:**
```python
from typing import Protocol, runtime_checkable

@runtime_checkable
class ToolRunner(Protocol):
    """Единый интерфейс для всех внешних инструментов."""

    name: str              # Имя инструмента (например, "naabu")

    def check_available(self) -> bool:
        """Проверить что инструмент установлен и доступен."""
        ...

    async def run(self, args: list[str], timeout: int = 300) -> ToolOutput:
        """Запустить инструмент. НИКОГДА shell=True."""
        ...

    def parse(self, raw_output: str) -> StructuredResult:
        """Распарсить raw output в структурированные данные."""
        ...

class ToolOutput:
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    command: list[str]       # Для аудит-лога
```

**Правила безопасности subprocess:**
- `subprocess.run()` / `asyncio.create_subprocess_exec()` — ТОЛЬКО с аргументами-списками
- **ЗАПРЕЩЕНО:** `shell=True`, строковая интерполяция аргументов
- Все аргументы проходят через `shlex.quote()` как дополнительная защита
- Таймаут на каждый subprocess через `asyncio.wait_for()`
- При таймауте: SIGTERM → 5 сек ожидание → SIGKILL

**Реестр инструментов:**
```python
# Каждый инструмент регистрируется в реестре
TOOL_REGISTRY: dict[str, type[ToolRunner]] = {
    "dig": DigRunner,
    "whois": WhoisRunner,
    "subfinder": SubfinderRunner,
    "naabu": NaabuRunner,
    "nuclei": NucleiRunner,
    "whatweb": WhatwebRunner,
    "openssl": OpensslRunner,
}
```

---

### 3.4 Recon Package
**Директория:** `modules/recon/`

**Файлы:**

| Файл | Функция | Инструмент | Вывод |
|------|---------|------------|-------|
| `dns.py` | `dns_enumerate()` | `dig`, `nslookup` | DNS записи (A, AAAA, MX, NS, TXT) |
| `whois.py` | `whois_lookup()` | `whois` | Whois данные (org, dates, contacts) |
| `subdomains.py` | `subdomain_enum()` | `subfinder` или crt.sh API | Список субдоменов |
| `certificates.py` | `certificate_info()` | `openssl s_client` | SSL сертификат (dates, issuer, SAN) |

**Конфигурация:**
```yaml
recon:
  dns:
    servers: ["8.8.8.8", "1.1.1.1"]
    timeout: 5
  subdomains:
    sources: ["crt.sh", "subfinder"]
    max_results: 100
  whois:
    cache_enabled: true
    cache_ttl_hours: 24
```

---

### 3.5 Analysis Package
**Директория:** `modules/analysis/`

**Файлы:**

| Файл | Функция | Инструмент | Вывод |
|------|---------|------------|-------|
| `ports.py` | `port_scan()` | `naabu` или `nmap` | Открытые порты + сервисы |
| `headers.py` | `web_headers()` | `curl` + парсинг | HTTP заголовки |
| `techstack.py` | `tech_stack()` | `whatweb` | CMS, фреймворки, сервер |
| `ssl.py` | `ssl_check()` | `testssl.sh` или `openssl` | TLS версия, cipher, expiry |
| `security_headers.py` | `security_headers()` | кастомная логика | Отсутствие HSTS, X-Frame, CSP |
| `nuclei.py` | `nuclei_scan()` | `nuclei` | Уязвимости (только info/low) |

**Конфигурация:**
```yaml
analysis:
  ports:
    tool: "naabu"  # или "nmap"
    top_ports: 1000
    timeout: 300
  web:
    user_agent: "Argus-Lite/1.0 (Security Audit)"
    follow_redirects: true
    max_redirects: 3
  nuclei:
    templates: ["exposures/", "misconfiguration/"]
    severity: ["info", "low"]          # ЖЁСТКИЙ ПОТОЛОК: максимум "low"
    max_allowed_severity: "low"        # Валидируется в коде, нельзя переопределить в конфиге
    rate_limit: 50
```

**Enforcement severity (жёсткий потолок):**
```python
# В коде, НЕ в конфиге — пользователь не может обойти
NUCLEI_MAX_SEVERITY = "low"
ALLOWED_SEVERITIES = {"info", "low"}

def validate_nuclei_config(config: NucleiConfig) -> None:
    """Валидация при загрузке конфига. Отклоняет medium/high/critical."""
    for sev in config.severity:
        if sev not in ALLOWED_SEVERITIES:
            raise ConfigValidationError(
                f"Severity '{sev}' запрещена. Допустимо: {ALLOWED_SEVERITIES}"
            )
```

---

### 3.6 Report Package
**Директория:** `modules/report/`

**Форматы:**

#### JSON (машиночитаемый)
```json
{
  "scan_id": "uuid",
  "target": "example.com",
  "started_at": "2026-03-21T10:00:00Z",
  "completed_at": "2026-03-21T10:15:00Z",
  "status": "completed",
  "summary": {
    "subdomains_found": 5,
    "open_ports": 3,
    "technologies": 7,
    "vulnerabilities": 2
  },
  "findings": [...],
  "evidence": {...}
}
```

#### Markdown (человекочитаемый)
```markdown
# Security Scan Report
## Target: example.com
## Date: 2026-03-21

### Summary
| Metric | Count |
|--------|-------|
| Subdomains | 5 |
| Open Ports | 3 |
| Technologies | 7 |
| Vulnerabilities | 2 |

### Findings
#### [INFO] Missing Security Headers
- HSTS: Not set
- X-Frame-Options: Not set

#### [LOW] Outdated Technology
- WordPress 5.8.0 (latest: 6.4.0)
```

#### HTML (опционально)
- Стильный отчёт с цветовой кодировкой severity
- Графики/диаграммы (опционально)

---

## 4. Структура данных

### 4.1 Scan Result Schema (агрегатор)

Все модели — Pydantic `BaseModel`. Каждый модуль возвращает свою модель результата, `ScanResult` только агрегирует их.

```python
class ReconResult(BaseModel):
    """Результат модуля разведки."""
    dns_records: list[DNSRecord] = []
    subdomains: list[Subdomain] = []
    whois_info: WhoisInfo | None = None
    certificate_info: CertificateInfo | None = None

class AnalysisResult(BaseModel):
    """Результат модуля анализа."""
    open_ports: list[Port] = []
    technologies: list[Technology] = []
    ssl_info: SSLInfo | None = None
    security_headers: SecurityHeadersResult | None = None
    nuclei_findings: list[NucleiFinding] = []

class ScanResult(BaseModel):
    """Агрегатор результатов. Не знает о внутренностях модулей."""
    scan_id: str           # UUID
    target: str            # Исходная цель
    target_type: str       # domain/ip/url
    status: str            # running/completed/failed/interrupted
    started_at: datetime
    completed_at: datetime | None = None

    # Результаты по модулям (каждый модуль — свой объект)
    recon: ReconResult = ReconResult()
    analysis: AnalysisResult = AnalysisResult()

    # Агрегированные findings из всех модулей
    findings: list[Finding] = []
    vulnerabilities: list[Vulnerability] = []

    # Метаданные
    tools_used: list[str] = []
    config_snapshot: dict = {}
    audit_log: list[AuditEntry] = []

    # Partial results support
    completed_stages: list[str] = []
    skipped_stages: list[str] = []
    errors: list[StageError] = []
```

### 4.2 Finding Schema
```python
class Finding:
    id: str
    type: str              # missing_header, outdated_software, exposed_file
    severity: str          # INFO/LOW (MEDIUM/HIGH/CRITICAL запрещены в MVP scope)
    title: str
    description: str
    asset: str             # К какому активу относится
    evidence: str          # Подтверждение (заголовок, ответ, скриншот)
    source: str            # Какой инструмент нашёл
    remediation: str       # Рекомендация по исправлению
    false_positive: bool   # Флаг для ручной проверки
```

### 4.3 Vulnerability Schema
```python
class Vulnerability:
    id: str
    finding_id: str        # Ссылка на Finding
    cve: Optional[str]     # CVE ID если есть
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    exploit_available: bool
    references: List[str]  # Ссылки на advisories
```

---

## 5. Конфигурация

### 5.1 Файлы конфигурации
| Файл | Назначение |
|------|------------|
| `~/.argus-lite/config.yaml` | Глобальные настройки |
| `~/.argus-lite/presets.yaml` | Пресеты сканирования |
| `~/.argus-lite/allowlist.txt` | Разрешённые цели (одна на строку) |
| `~/.argus-lite/denylist.txt` | Запрещённые цели |

### 5.2 Пример config.yaml
```yaml
# ~/.argus-lite/config.yaml

general:
  log_level: INFO
  log_dir: ~/.argus-lite/logs
  scan_dir: ~/.argus-lite/scans

security:
  require_confirmation: true
  allowlist_only: false
  max_scan_duration_minutes: 120

rate_limits:
  global_rps: 50
  per_target_rps: 10
  concurrent_requests: 5

tools:
  subfinder:
    enabled: true
    path: /usr/bin/subfinder
  naabu:
    enabled: true
    path: /usr/bin/naabu
  nuclei:
    enabled: true
    path: /usr/bin/nuclei
    templates_dir: ~/nuclei-templates
  whatweb:
    enabled: true
    path: /usr/bin/whatweb

api_keys:
  # Рекомендуется использовать env-переменные вместо хранения в файле:
  # ARGUS_SHODAN_KEY, ARGUS_VIRUSTOTAL_KEY
  shodan: ""  # опционально, переопределяется $ARGUS_SHODAN_KEY
  virustotal: ""  # опционально, переопределяется $ARGUS_VIRUSTOTAL_KEY
  crtsh: ""  # не требуется
```

**Безопасность конфигурации:**
- При загрузке конфига проверяются права файла: если не `0600`, выводится предупреждение
- Env-переменные `ARGUS_*` имеют приоритет над значениями в YAML
- API-ключи **никогда** не попадают в аудит-лог и отчёты
- `argus-lite init` создаёт конфиг с правами `0600` автоматически

### 5.3 Пример presets.yaml
```yaml
presets:
  quick:
    description: "Быстрая проверка (5-10 мин)"
    stages:
      - passive_recon
      - web_headers
      - tech_stack
    tools:
      - whatweb
      - curl
    nuclei: false

  full:
    description: "Полное сканирование (30-60 мин)"
    stages:
      - passive_recon
      - active_recon
      - port_scan
      - web_analysis
      - vulnerability_scan
    tools:
      - subfinder
      - naabu
      - whatweb
      - nuclei
    nuclei:
      severity: [info, low]  # Жёсткий потолок: max "low" (enforced в коде)

  recon:
    description: "Только разведка (без активных проверок)"
    stages:
      - passive_recon
    tools:
      - subfinder
      - dig
      - whois
    safe_mode: true

  web:
    description: "Веб-ориентированное сканирование"
    stages:
      - web_headers
      - tech_stack
      - ssl_check
      - security_headers
      - vulnerability_scan
    tools:
      - whatweb
      - nuclei
      - openssl
```

---

## 6. Безопасность и аудит

### 6.1 Input Sanitization (первый рубеж)
**Проверки ДО любых действий:**
```python
import re

# Strict regex — только допустимые символы
DOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,253}[a-zA-Z0-9]$')
IP_REGEX = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
SHELL_DANGEROUS = re.compile(r'[;|$`&><\\\'"(){}\[\]!#~]')

def sanitize_target(target: str) -> str:
    """Очистка и валидация target. Вызывается ПЕРВЫМ."""
    target = target.strip().lower()

    # Отклонить любые shell-метасимволы
    if SHELL_DANGEROUS.search(target):
        raise InputSanitizationError(
            f"Target содержит запрещённые символы: {target}"
        )

    # Валидация формата
    if not (DOMAIN_REGEX.match(target) or IP_REGEX.match(target)):
        raise InputSanitizationError(
            f"Невалидный формат target: {target}"
        )

    return target
```

### 6.2 Scope Enforcement
**Проверки после санитизации:**
```python
def validate_scope(target: str, config: Config) -> ValidationResult:
    checks = [
        check_allowlist(target, config.allowlist),
        check_denylist(target, config.denylist),
        check_local_network(target),  # предупреждение для 192.168.x.x
        check_reserved_ranges(target),  # 10.x.x.x, 172.16-31.x.x
        check_confirmation(config.require_confirmation),
    ]
    return all(checks)
```

### 6.3 Subprocess Safety
**Обязательные правила выполнения внешних инструментов:**
```python
# ПРАВИЛЬНО: аргументы списком
result = await asyncio.create_subprocess_exec(
    "/usr/bin/naabu", "-host", target, "-top-ports", "1000",
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
)

# ЗАПРЕЩЕНО: shell=True, строковая интерполяция
# subprocess.run(f"naabu -host {target}", shell=True)  # НИКОГДА!
```

### 6.4 Audit Log Format
```json
{
  "timestamp": "2026-03-21T10:00:00Z",
  "action": "scan_started",
  "actor": "user@kali",
  "target": "example.com",
  "scan_id": "uuid",
  "config_hash": "sha256(...)",
  "confirmation": true
}
```

### 6.5 Safe Defaults
| Настройка | Значение | Обоснование |
|-----------|----------|-------------|
| `max_concurrent_requests` | 5 | Избегание DoS |
| `rate_limit_rps` | 10 | Уважение к целевым серверам |
| `nuclei_severity` | info,low | Без деструктивных проверок |
| `require_confirmation` | true | Явное согласие пользователя |
| `allow_exploitation` | false | Запрещено в MVP |

---

## 7. Зависимости и требования

### 7.1 Системные требования
- **OS:** Kali Linux 2024+ (или Debian/Ubuntu с инструментами)
- **Python:** 3.10+
- **RAM:** 2GB минимум, 4GB рекомендовано
- **Disk:** 500MB для установки + место под отчёты

### 7.2 Внешние инструменты (должны быть установлены)
| Инструмент | Назначение | Установка в Kali |
|------------|------------|------------------|
| `dig` | DNS запросы | `dnsutils` (pre-installed) |
| `whois` | Whois lookup | `whois` (pre-installed) |
| `subfinder` | Субдомены | `go install github.com/projectdiscovery/subfinder` |
| `naabu` | Скан портов | `go install github.com/projectdiscovery/naabu` |
| `nuclei` | Уязвимости | `go install github.com/projectdiscovery/nuclei` |
| `whatweb` | Tech stack | `apt install whatweb` |
| `openssl` | SSL check | `openssl` (pre-installed) |
| `jq` | JSON парсинг | `apt install jq` |

### 7.3 Python зависимости
```txt
# requirements.txt
click>=8.0           # CLI framework
pyyaml>=6.0          # Config parsing
httpx>=0.25          # Async HTTP (замена requests для asyncio)
python-dateutil>=2.8 # Date handling
rich>=13.0           # Progress bars, live display, красивый вывод
pydantic>=2.0        # Валидация данных и моделей
jinja2>=3.1          # HTML report templating
# uuid — стандартная библиотека Python, отдельный пакет не нужен
# asyncio — стандартная библиотека Python 3.10+
```

---

## 8. Структура проекта

```
argus-lite/
├── README.md
├── LICENSE
├── pyproject.toml            # Заменяет setup.py (PEP 517/518)
├── requirements.txt          # Для pip install -r (дублирует pyproject.toml)
├── config/
│   ├── default_config.yaml
│   └── presets.yaml
├── src/
│   └── argus_lite/           # Proper namespace package
│       ├── __init__.py
│       ├── cli.py            # Точка входа (Click)
│       ├── core/
│       │   ├── __init__.py
│       │   ├── orchestrator.py  # Главный координатор
│       │   ├── config.py        # Загрузка конфига + валидация
│       │   ├── validator.py     # Валидация и санитизация цели
│       │   ├── tool_runner.py   # Абстракция запуска инструментов
│       │   ├── rate_limiter.py  # Rate limiting (asyncio.Semaphore)
│       │   └── audit.py         # Аудит логирование
│       ├── modules/
│       │   ├── __init__.py
│       │   ├── recon/           # Пакет разведки
│       │   │   ├── __init__.py
│       │   │   ├── dns.py
│       │   │   ├── whois.py
│       │   │   ├── subdomains.py
│       │   │   └── certificates.py
│       │   ├── analysis/        # Пакет анализа
│       │   │   ├── __init__.py
│       │   │   ├── ports.py
│       │   │   ├── headers.py
│       │   │   ├── techstack.py
│       │   │   ├── ssl.py
│       │   │   ├── security_headers.py
│       │   │   └── nuclei.py
│       │   └── report/          # Пакет отчётов
│       │       ├── __init__.py
│       │       ├── json_report.py
│       │       ├── markdown_report.py
│       │       └── html_report.py
│       ├── tools/               # Реализации ToolRunner для каждого инструмента
│       │   ├── __init__.py
│       │   ├── dig_runner.py
│       │   ├── whois_runner.py
│       │   ├── subfinder_runner.py
│       │   ├── naabu_runner.py
│       │   ├── nuclei_runner.py
│       │   ├── whatweb_runner.py
│       │   └── openssl_runner.py
│       ├── utils/
│       │   ├── __init__.py
│       │   ├── logger.py        # Логирование
│       │   ├── http.py          # HTTP утилиты
│       │   └── progress.py      # Rich progress bars
│       └── models/
│           ├── __init__.py
│           ├── scan.py          # ScanResult (агрегатор)
│           ├── recon.py         # ReconResult
│           ├── analysis.py      # AnalysisResult
│           ├── finding.py       # Finding, Vulnerability
│           └── target.py        # Target validation models
├── tests/
│   ├── conftest.py              # Shared fixtures
│   ├── fixtures/                # Захваченный output инструментов
│   │   ├── naabu_output.json
│   │   ├── nuclei_output.json
│   │   ├── dig_output.txt
│   │   └── whatweb_output.json
│   ├── test_orchestrator.py
│   ├── test_validator.py
│   ├── test_tool_runner.py
│   ├── test_sanitization.py     # Input sanitization tests
│   ├── test_recon/
│   │   ├── test_dns.py
│   │   ├── test_whois.py
│   │   └── test_subdomains.py
│   ├── test_analysis/
│   │   ├── test_ports.py
│   │   ├── test_headers.py
│   │   ├── test_nuclei.py
│   │   └── test_security_headers.py
│   └── test_report/
│       ├── test_json_report.py
│       └── test_markdown_report.py
└── examples/
    ├── sample_report.md
    └── sample_config.yaml
```

**pyproject.toml (основной файл сборки):**
```toml
[build-system]
requires = ["setuptools>=68.0", "setuptools-scm"]
build-backend = "setuptools.build_meta"

[project]
name = "argus-lite"
version = "1.0.0"
description = "Local security scanner for authorized penetration testing"
requires-python = ">=3.10"
dependencies = [
    "click>=8.0",
    "pyyaml>=6.0",
    "requests>=2.28",
    "python-dateutil>=2.8",
    "rich>=13.0",
    "pydantic>=2.0",
]

[project.scripts]
argus-lite = "argus_lite.cli:main"
```

---

## 9. План реализации (Phases)

### Phase 1: Safety Foundation (Неделя 1) — КРИТИЧНО
> Все механизмы безопасности реализуются ДО интеграции внешних инструментов.

- [ ] Структура проекта + pyproject.toml + namespace `argus_lite`
- [ ] CLI skeleton с Click (scan/init/list/config/tools команды)
- [ ] Загрузка конфигурации из YAML + Pydantic валидация
- [ ] Input sanitization (strict regex, отклонение shell-метасимволов)
- [ ] Scope validation (allowlist/denylist/confirmation prompt)
- [ ] ToolRunner абстракция (subprocess safety, никогда shell=True)
- [ ] Rate limiter (asyncio.Semaphore + token bucket)
- [ ] Базовое логирование + аудит-лог
- [ ] `argus-lite init` — генерация конфига с chmod 600
- [ ] `argus-lite tools check` — проверка доступности инструментов
- [ ] Тесты: sanitization, scope validation, config validation

### Phase 2: Recon Package (Неделя 2)
- [ ] DNS enumeration (dig) — через ToolRunner
- [ ] Whois lookup — через ToolRunner
- [ ] Subdomain enum (crt.sh API + subfinder) — через ToolRunner
- [ ] SSL certificate info (openssl) — через ToolRunner
- [ ] Сохранение raw output + ReconResult модель
- [ ] Тесты: fixture-based парсинг output каждого инструмента

### Phase 3: Analysis Package (Неделя 3)
- [ ] Port scan (naabu wrapper) — через ToolRunner
- [ ] Web headers (httpx/curl + парсинг) — через ToolRunner
- [ ] Tech stack (whatweb wrapper) — через ToolRunner
- [ ] Security headers check (кастомная логика)
- [ ] Nuclei integration (severity ceiling enforced в коде: max "low")
- [ ] AnalysisResult модель
- [ ] Тесты: fixture-based парсинг + nuclei severity enforcement

### Phase 4: Report Package (Неделя 4)
- [ ] JSON export
- [ ] Markdown export
- [ ] HTML export (опционально)
- [ ] Summary statistics
- [ ] Finding deduplication
- [ ] Partial results support (interrupted scans)
- [ ] Тесты: генерация отчётов из fixture-данных

### Phase 5: Resilience & UX (Неделя 5)
- [ ] Graceful shutdown (SIGINT/SIGTERM → partial save)
- [ ] Rich progress bars для длительных сканирований
- [ ] Error classification + retry logic для transient ошибок
- [ ] asyncio конкурентность внутри этапов
- [ ] Integration tests (end-to-end с mock-инструментами)

### Phase 6: Polish (Неделя 6)
- [ ] Documentation (README, usage examples, legal notice)
- [ ] Config templates
- [ ] Bash/Zsh completion
- [ ] Dockerfile (опционально)
- [ ] Coverage check (>70%)
- [ ] Release v1.0

---

## 10. Тестовые сценарии

### 10.1 Легальные цели для тестирования
```bash
# Локальные тестовые цели
argus-lite scan localhost --preset quick
argus-lite scan 127.0.0.1 --preset recon

# Тестовые уязвимые стенды (локально)
argus-lite scan dvwa.local --preset full
argus-lite scan metasploitable.local --preset web

# Твой реальный сайт (только если твой!)
argus-lite scan yoursite.com --preset quick --confirm
```

### 10.2 Проверка безопасности
```bash
# Попытка сканирования запрещённой цели
argus-lite scan google.com --preset full
# Ожидается: предупреждение + требование подтверждения

# Проверка rate limiting
argus-lite scan test.local --rate-limit 1 --preset full
# Ожидается: сканирование с лимитом 1 запрос/сек

# Проверка аудита
cat ~/.argus-lite/logs/audit.log
# Ожидается: запись всех действий
```

---

## 11. Критерии готовности v1.0

| Критерий | Статус |
|----------|--------|
| Все модули работают (CLI, Recon, Analysis, Report) | ⬜ |
| Input sanitization блокирует shell injection | ⬜ |
| Subprocess safety: нигде нет shell=True | ⬜ |
| Nuclei severity ceiling enforced в коде (max "low") | ⬜ |
| Конфигурация загружается из YAML с Pydantic валидацией | ⬜ |
| API-ключи поддерживают env-переменные | ⬜ |
| Отчёты генерируются в JSON + Markdown | ⬜ |
| Scope validation работает (allowlist/denylist) | ⬜ |
| Аудит логирование включено | ⬜ |
| Rate limiting реализован | ⬜ |
| Graceful shutdown сохраняет partial results | ⬜ |
| `argus-lite init` и `argus-lite tools check` работают | ⬜ |
| Tests покрывают >70% кода (fixture-based) | ⬜ |
| README с примерами использования | ⬜ |
| Предупреждение о легальности в CLI | ⬜ |

---

## 12. Предупреждение о легальности

**Обязательно добавить в:**
1. **README.md** (первый раздел)
2. **CLI output** (при запуске сканирования)
3. **Отчёты** (футер каждого отчёта)

```
⚠️  LEGAL NOTICE

This tool is intended for authorized security testing only.
Always obtain written permission before scanning any system you do not own.
Unauthorized scanning may violate computer crime laws in your jurisdiction.

The authors are not responsible for misuse of this tool.
By using Argus Lite, you acknowledge that you have proper authorization.
```
