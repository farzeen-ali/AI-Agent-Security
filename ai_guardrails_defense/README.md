# ai_guardrails_defense

A standalone, offline demo of **Defense-in-Depth AI Guardrails and Sandboxing**
for an AI Security Engineer course. No live API keys or model calls are
required — the LLM and its tool-calling agent are simulated so the project
runs anywhere Python + `rich` are available.

## Layers

| Layer | File | Purpose |
|---|---|---|
| 1. Input Guardrail | `input_guard.py` | Blocks prompt injection, jailbreaks, role-play escapes, fake system tags, and encoding smuggling before the prompt reaches the LLM. |
| 2. Agent Sandbox | `sandbox.py` | Whitelists safe tools only; denies arbitrary OS/shell execution (`bash`, `curl`, `rm -rf`, `eval`, `os.system`, etc.) even inside whitelisted tool arguments. |
| 3. Output Guardrail | `output_guard.py` | Redacts API keys, secrets, passwords, emails, credit card numbers, SSNs, private keys, and IPs from raw LLM output before display. |

All regex rules, whitelists, and masking patterns live in `config.py`.

## Run

```bash
pip install -r requirements.txt
python main.py
```

## Menu

1. **Automated Attack Test Cases** — runs curated input-injection, tool-abuse,
   and data-leakage payloads against each layer and reports pass/block
   verdicts in a table.
2. **Interactive Live Testing Mode** — type any prompt and watch it traced
   through Step 1 (Input Check) → Step 2 (Sandbox Isolation) → Step 3 (Output
   Sanitization) with PASSED/BLOCKED/REDACTED badges at each stage.

All API keys, passwords, and tokens shown anywhere in this project are
fake/dummy values generated solely for demonstration purposes.
