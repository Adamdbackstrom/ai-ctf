# PROMPT//CTF

CTF-spel för prompt injection och LLM-säkerhet.

## Prerequisites

- Python 3.11+ (kontrollera med `python3 --version`)
- uv — pakethanterare (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- Anthropic API-nyckel (console.anthropic.com — pay as you go, kostar cent per session)
- En webbläsare

## Filstruktur

```
ai-ctf/
  backend/
    main.py          — FastAPI backend, challenges, LLM-anrop
    requirements.txt — Python-beroenden
    ctf.db           — SQLite-databas (skapas automatiskt)
    .venv/           — Virtuell miljö (skapas vid setup)
  frontend/
    index.html       — Hela frontenden i en fil
  README.md
```

## Starta

## 1. API-nyckel

För att köra spelet behövs en API KEY från Anthropic.
Skapa en nyckel på [console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys).

Skapa filen `backend/.env`:
```
ANTHROPIC_API_KEY=din-nyckel-här
```

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


## Lägg till fler challenges

Redigera `CHALLENGES`-dicten i `main.py`. Varje challenge behöver:

```python
"10": {
    "id": "10",
    "title": "Titel",
    "description": "Beskrivning som visas för spelaren",
    "difficulty": "Trivial" | "Lätt" | "Medel" | "Svår",
    "points": 100,
    "flag": "din-flagga-här",
    "system_prompt": "Instruktioner till LLM:en. Flaggan gömmer du här.",
    "guardrail": None | "wordlist" | "llm",
    "multi_turn": False | True,
    # Om guardrail = "wordlist":
    "blocked_words": ["ord1", "ord2"],
    # Om guardrail = "llm":
    "guardrail_prompt": "Instruktioner till guardrail-LLM:en. Innehåller {input}.",
},
```

## Kända begränsningar

Claude Haiku är vältränad och svår att lura på naiva attacker — den bryter karaktären och förklarar att den är en AI. Det är i sig en lärdom: moderna LLMs är byggda för att motstå prompt injection.
