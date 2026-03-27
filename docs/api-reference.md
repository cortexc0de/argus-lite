# API Reference

## Dashboard REST API

The Argus web dashboard exposes a REST API at `http://127.0.0.1:8443/api/`.

### Endpoints

#### `GET /api/scans`
List all completed scans.

**Response:**
```json
[
  {
    "scan_id": "abc-123",
    "target": "example.com",
    "status": "completed",
    "started_at": "2025-01-15T10:00:00Z",
    "total_findings": 5,
    "risk_level": "HIGH"
  }
]
```

#### `GET /api/scans/{id}`
Get detailed scan results.

**Response:** Full `ScanResult` object including recon, analysis, findings, and vulnerabilities.

#### `GET /api/compare?a={id}&b={id}`
Compare two scans side by side.

**Response:**
```json
{
  "added_findings": [...],
  "removed_findings": [...],
  "unchanged_findings": [...]
}
```

#### `GET /api/stats`
Get aggregate statistics.

**Response:**
```json
{
  "total_scans": 42,
  "total_findings": 156,
  "severity_distribution": {"INFO": 50, "LOW": 40, "MEDIUM": 30, "HIGH": 20, "CRITICAL": 16},
  "top_finding_types": [{"type": "xss", "count": 25}, ...]
}
```

#### `POST /api/scans`
Launch a new scan.

**Request:**
```json
{
  "target": "example.com",
  "preset": "full",
  "ai_enabled": false
}
```

## Data Models

### ScanResult
```python
class ScanResult(BaseModel):
    scan_id: str
    target: str
    target_type: str        # "domain", "ip", "url"
    status: str             # "running", "completed", "interrupted"
    started_at: datetime
    completed_at: datetime | None
    recon: ReconResult
    analysis: AnalysisResult
    findings: list[Finding]
    vulnerabilities: list[Vulnerability]
    tools_used: list[str]
    risk_summary: dict | None
```

### Finding
```python
class Finding(BaseModel):
    id: str
    type: str               # "xss", "sqli", "nuclei", "exposed_service", etc.
    severity: str           # "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    title: str
    description: str
    asset: str
    evidence: str
    source: str             # Tool that found it
    remediation: str
    false_positive: bool
```

### SkillResult
```python
@dataclass
class SkillResult:
    success: bool
    data: dict
    findings: list[Finding]
    summary: str
    error: str
```
