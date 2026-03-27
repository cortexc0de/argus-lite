# Agent Guide

The Argus agent is an autonomous pentesting AI that plans, executes, and adapts.

## Basic Usage

```bash
argus agent example.com
```

## Modes

### Single Agent (default)
One agent with access to all 11 skills. Plans and executes autonomously.

### Multi-Agent Team
Three specialized agents with restricted skill sets:

```bash
argus agent example.com --multi-agent
```

Recon → Vuln Scanner → Exploit, each with its own LLM decision loop.

### Stealth Mode
Slow probing with randomized headers and WAF evasion:

```bash
argus agent example.com --stealth
```

## Missions

Direct the agent toward a specific objective:

```bash
argus agent example.com --mission data_exfiltration
argus agent example.com --mission admin_access
argus agent example.com --mission rce
argus agent example.com --mission full_assessment  # default
```

The agent builds a goal hierarchy from the mission and tracks progress.

## Agent Loop

```
1. Recon (quick scan via orchestrator)
2. Environment detection (WAF/CDN fingerprinting)
3. Intelligence layer:
   - Goal hierarchy from mission
   - Knowledge base patterns for detected tech
   - Target scoring (prioritize endpoints)
   - Meta-learning (skill effectiveness)
4. Plan creation (LLM builds attack plan)
5. Execute loop (max_steps iterations):
   a. LLM decides next action
   b. Skill executes
   c. Results feed back (attack graph, findings)
   d. Meta-learner records outcome
   e. Plan adapts if needed
6. Save state (memory, knowledge, meta stats)
```

## Configuration

### Max Steps
Control how many decision loops the agent runs:

```bash
argus agent example.com --max-steps 15  # default: 8
```

### AI Provider
The agent needs an LLM API:

```bash
export ARGUS_AI_KEY="your-key"
# Or configure via: argus config ai
```

Works with OpenAI, Ollama, vLLM, or any OpenAI-compatible API.

### Custom Skills
Add domain-specific skills:

```bash
argus agent example.com --skills-dir ./my-skills
```

See [Custom Skills](skills/custom-skills.md).

## Memory

The agent learns across sessions:
- **Target patterns**: tech stack + ports seen on past targets
- **Successful payloads**: what worked on similar targets
- **Findings history**: what was found before

Memory is stored at `~/.argus-lite/agent_memory.json`.
