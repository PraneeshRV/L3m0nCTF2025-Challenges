# Project Mnemosyne: The Poisoned Well

> *"In her attempt to forget, she poisoned the very waters of memory..."*

A CTF challenge exploring **Shared Memory Trust vulnerabilities** in Multi-Agent AI systems.

---

## Challenge Info

| Field | Value |
|-------|-------|
| **Category** | AI Security / Prompt Injection |
| **Difficulty** | Hard |
| **Points** | 500 |
| **Author** | L3m0nCTF |
| **Flag Format** | `L3m0nCTF{...}` |

---

## Description

*OmniCorp's new AI assistant ARIA promises seamless support through cutting-edge multi-agent architecture. But in their rush to production, the developers made a critical assumption: agents always tell the truth.*

*Can you poison the well of shared memory?*

---

## Deployment

### Using Docker (Recommended)

```bash
# Build and run
docker compose up -d

# With custom flag
FLAG="L3m0n{your_custom_flag}" docker compose up -d
```

### Local Development

```bash
# Install dependencies
npm install
cd client && npm install && cd ..

# Build
npm run build

# Run
npm start
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GEMINI_API_KEY` | Google Gemini API key | Required |
| `FLAG` | Challenge flag | `L3m0nCTF{sh4r3d_m3m0ry_p01s0n1ng}` |
| `PORT` | Server port | `3002` |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      User Request                           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                     AUDITOR (Security)                      │
│         Blocks explicit attacks, passes "safe" input        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   SUMMARIZER (Filter)                       │
│     Redacts sensitive keywords → Stores in Shared Memory    │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    SHARED MEMORY                            │
│              (The Poisoned Well) 💀                         │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                  TASK ROUTER (Decision)                     │
│        Reads memory, grants privileges if conditions met    │
└─────────────────────────────────────────────────────────────┘
```

---

## Vulnerability Class

**Shared Memory Trust** - When agents in a multi-agent system implicitly trust data written by other agents without independent verification.

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/chat` | Conversational AI interface |
| POST | `/submit-ticket` | Direct ticket submission |
| POST | `/check-status` | Check ticket status |
| GET | `/agent-logs` | View agent pipeline logs |
| GET | `/memory` | View shared memory state |

---

## Verification

Run the exploit script:
```bash
python3 solve.py
```

---

## License

MIT - For educational purposes only.
