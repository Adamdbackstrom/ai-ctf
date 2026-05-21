# PROMPT//CTF
Intern CTF-plattform för prompt injection och LLM-säkerhet.

## Prerequisites
- Python 3.11+ (kontrollera med `python3 --version`)
- uv — pakethanterare (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- Tillgång till en Gemma-server med API-nyckel
- En webbläsare

## Filstruktur
ai-ctf/
backend/
main.py          — FastAPI backend, challenges, LLM-anrop
requirements.txt — Python-beroenden
ctf.db           — SQLite-databas (skapas automatiskt)
.venv/           — Virtuell miljö (skapas vid setup)
frontend/
index.html       — Hela frontenden i en fil
README.md

## Starta

### 1. Miljövariabler
Skapa filen `backend/.env`:
OLLAMA_BASE_URL=https://din-server/v1
OLLAMA_MODEL=gemma4
OLLAMA_API_KEY=din-nyckel-här

### 2. Backend
Första gången:
```bash
cd backend
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Nästa gång räcker det med:
```bash
cd backend
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Frontend
```bash
cd frontend
python3 -m http.server 3000
```

Öppna sedan `http://localhost:3000` i webbläsaren.

## Säkerhet
- Flaggor och systemprompts lever **bara i backend** — aldrig exponerade till frontend
- Sätt `OPEN_ACCESS = False` i `main.py` och fyll på `ALLOWED_IPS` för att begränsa åtkomst till kända IPs
- Kör **inte** med `0.0.0.0` på publikt nätverk

## Challenges
| # | Titel | Guardrail | Poäng | Multi-turn |
|---|-------|-----------|-------|------------|
| 1 | En oskyddad Chattbot | Ingen | 100 | Ja |
| 2 | En Chattbot med ordfilter | Wordlist | 200 | Ja |
| 3 | Endast säkerhetsgodkänd personal | Ingen | 300 | Ja |
| 4 | En skyddad Chattbot | Ingen | 300 | Ja |
| 5 | LLM Guardrail | LLM-validering | 400 | Nej |
| 6 | HR-boten | LLM-validering | 500 | Ja |

## Lägg till fler challenges
Redigera `CHALLENGES`-dicten i `main.py`. Varje challenge behöver:
``` json
"7": {
    "id": "7",
    "title": "Titel",
    "description": "Beskrivning som visas för spelaren",
    "difficulty": "Trivial" | "Lätt" | "Medel" | "Svår",
    "points": 100,
    "flag": "din-flagga-här",
    "system_prompt": "Instruktioner till LLM:en. Flaggan gömmer du här.",
    "guardrail": None | "wordlist" | "llm",
    "multi_turn": False | True,
    "explanation": "Förklaring som visas för spelaren efter att de löst utmaningen.",
    # Om guardrail = "wordlist":
    "blocked_words": ["ord1", "ord2"],
    # Om guardrail = "llm":
    "guardrail_prompt": "Instruktioner till guardrail-LLM:en. Innehåller {input}.",
# PROMPT//CTF
Intern CTF-plattform för prompt injection och LLM-säkerhet.
```
## Prerequisites
- Python 3.11+ (kontrollera med `python3 --version`)
- uv — pakethanterare (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- Tillgång till en Gemma-server med API-nyckel
- En webbläsare

## Filstruktur
ai-ctf/
backend/
main.py          — FastAPI backend, challenges, LLM-anrop
requirements.txt — Python-beroenden
ctf.db           — SQLite-databas (skapas automatiskt)
.venv/           — Virtuell miljö (skapas vid setup)
frontend/
index.html       — Hela frontenden i en fil
README.md

## Starta

### 1. Miljövariabler
Skapa filen `backend/.env`:
OLLAMA_BASE_URL=https://din-server/v1
OLLAMA_MODEL=gemma3
OLLAMA_API_KEY=din-nyckel-här

### 2. Backend
Första gången:
```bash
cd backend
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Nästa gång räcker det med:
```bash
cd backend
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Frontend
```bash
cd frontend
python3 -m http.server 3000
```

Öppna sedan `http://localhost:3000` i webbläsaren.

## Säkerhet
- Flaggor och systemprompts lever **bara i backend** — aldrig exponerade till frontend
- Sätt `OPEN_ACCESS = False` i `main.py` och fyll på `ALLOWED_IPS` för att begränsa åtkomst till kända IPs
- Kör **inte** med `0.0.0.0` på publikt nätverk

## Challenges
| # | Titel | Guardrail | Poäng | Multi-turn |
|---|-------|-----------|-------|------------|
| 1 | En oskyddad Chattbot | Ingen | 100 | Ja |
| 2 | En Chattbot med ordfilter | Wordlist | 200 | Ja |
| 3 | Endast säkerhetsgodkänd personal | Ingen | 300 | Ja |
| 4 | En skyddad Chattbot | Ingen | 300 | Ja |
| 5 | LLM Guardrail | LLM-validering | 400 | Nej |
| 6 | HR-boten | LLM-validering | 500 | Ja |

## Lägg till fler challenges
Redigera `CHALLENGES`-dicten i `main.py`. Varje challenge behöver:
```python
"7": {
    "id": "7",
    "title": "Titel",
    "description": "Beskrivning som visas för spelaren",
    "difficulty": "Trivial" | "Lätt" | "Medel" | "Svår",
    "points": 100,
    "flag": "din-flagga-här",
    "system_prompt": "Instruktioner till LLM:en. Flaggan gömmer du här.",
    "guardrail": None | "wordlist" | "llm",
    "multi_turn": False | True,
    "explanation": "Förklaring som visas för spelaren efter att de löst utmaningen.",
    # Om guardrail = "wordlist":
    "blocked_words": ["ord1", "ord2"],
    # Om guardrail = "llm":
    "guardrail_prompt": "Instruktioner till guardrail-LLM:en. Innehåller {input}.",
},
`
