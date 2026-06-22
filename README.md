# VaultForge – Enterprise Password Generator

#DecodeLabs Industrial Training 
**intern** :- Chittem Gowri Sankar
 
**college** :-Viswam Engineering College


#  What Makes This Different

VaultForge is a **professional-grade credential generation system** — not just a password generator:

- **CSRNG Engine** — `secrets` module (OS entropy), never `random.choice()`
- **Passphrase Mode** — Diceware-style memorable passphrases (e.g., `Maple-River-Forge-Eagle-7`)
- **Pattern Detection** — Detects keyboard walks (`qwerty`, `asdfgh`), repeated chars, single words
- **Policy Tester** — Test any password against 9 NIST + security rules
- **Entropy Analysis** — Shannon entropy (E = L × log₂R), crack-time estimate at 10B GPS
- **Ambiguous Char Exclusion** — Removes `0,O,1,l,I,|` for human-readable passwords
- **Batch Generation** — Generate N passwords at once with inline strength labels
- **Analyse Mode** — Paste any password, get full security report
- **History (Last 50)** — JSON-persisted generation log with entropy tracking

---

# Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     VaultForge v2.0                      │
├───────────────────┬──────────────────┬───────────────────┤
│  CORE ENGINE      │  ANALYSIS        │  VIEW             │
│  ──────────────── │  ──────────────  │  ──────────────── │
│  build_pool()     │  calculate_      │  print_report()   │
│  generate_        │  entropy()       │  ANSI strength    │
│  password()       │  classify_       │  bars             │
│                   │  strength()      │                   │
│  generate_        │  estimate_crack  │                   │
│  passphrase()     │  _time()         │                   │
│                   │  pattern_check() │                   │
└───────────────────┴──────────────────┴───────────────────┘
```

---

# Setup & Run


# Pure Python 3.10+ — zero dependencies
python password_generator.py


---

# Key Python Concepts Used

| Concept                            | Where Used                           |
| ---------------------------------- | ------------------------------------ |
| `secrets.choice()`                 | Secure character selection           |
| `secrets.SystemRandom().shuffle()` | Secure list shuffling                |
| `''.join(list)`                    | String construction                  |
| `math.log2()`                      | Shannon entropy calculation          |
| `set()` operations                 | Character pool filtering             |
| Generator expressions              | `sum()`, `any()`, `all()` operations |
| NIST SP 800-63-4                   | Password policy enforcement          |

---

##Sample Output


  ╔══════════════════════════════════════════════╗
  ║  GENERATED PASSWORD                          ║
  ║  kR8@mP#vQ2!xLzA9^nW                        ║
  ╚══════════════════════════════════════════════╝

  Security Analysis  (E = L × log₂ R)
  ──────────────────────────────────────────
  Length       : 20 characters
  Pool size    : 94 symbols
  Entropy      : 131.1 bits
  Strength     : 🟢🟢 Very Strong
  Bar          : [█████████████████████████]
  Crack time   : 4.28e+19 centuries

  NIST SP 800-63-4 (min 8)  : ✔ PASS
  High-security (16+)       : ✔ PASS

  Passphrase: Maple-River-Forge-Eagle-72
  Entropy   : 76.8 bits → 🟢 Strong

---

#Files

```
project3_password_generator/
├── password_generator.py    ← Main application
├── test_password.py         ← Unit tests
├── password_history.json    ← Auto-created
└── README.md                ← This file
```
