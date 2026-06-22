import secrets, string, math, json, os, sys
from datetime import datetime
from typing import Optional


_TTY = sys.stdout.isatty()
def _c(t, code): return f"\033[{code}m{t}\033[0m" if _TTY else t

RED    = lambda t: _c(t, "31")
GREEN  = lambda t: _c(t, "32")
YELLOW = lambda t: _c(t, "33")
CYAN   = lambda t: _c(t, "36")
BLUE   = lambda t: _c(t, "34")
BOLD   = lambda t: _c(t, "1")
DIM    = lambda t: _c(t, "2")

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS    = string.digits
SYMBOLS   = string.punctuation
AMBIGUOUS = set("0O1lI|")          # visually confusing chars

NIST_MIN    = 8
NIST_SECURE = 16

# Diceware-inspired wordlist (100 common English words, 4–7 letters)
WORDLIST = [
    "apple","brave","cloud","delta","eagle","flame","globe","honey",
    "ivory","jewel","karma","lemon","maple","noble","ocean","pearl",
    "queen","river","stone","tiger","ultra","vivid","water","xenon",
    "yacht","zebra","amber","blaze","cedar","dusk","ember","frost",
    "grace","halo","indie","jade","knack","lunar","mango","nexus",
    "orbit","pixel","quest","radar","solar","terra","unity","vault",
    "waltz","xray","yield","zesty","anchor","bridge","cipher","drift",
    "ether","flint","glyph","haven","index","joust","kinetic","loft",
    "magnet","nerve","onyx","prism","quartz","relay","sigma","twist",
    "umbra","vigor","whirl","xylem","young","zenith","agate","bliss",
    "crane","dagger","eight","forge","grant","holly","inner","jelly",
    "kneel","lance","mercy","nimble","oaken","plaza","quiet","runic",
    "sharp","tidal","upper","valor","witch","xeric","yonder","zonal",
]

# Common keyboard patterns to detect weak passwords
KEYBOARD_WALKS = ["qwerty","asdfgh","zxcvbn","qazwsx","1234567","abcdef"]


def build_pool(use_lower=True, use_upper=True, use_digits=True,
               use_symbols=True, exclude_ambiguous=False) -> str:
    pool = ""
    if use_lower:   pool += LOWERCASE
    if use_upper:   pool += UPPERCASE
    if use_digits:  pool += DIGITS
    if use_symbols: pool += SYMBOLS
    if exclude_ambiguous:
        pool = "".join(ch for ch in pool if ch not in AMBIGUOUS)
    return pool


def generate_password(length: int, use_lower=True, use_upper=True,
                      use_digits=True, use_symbols=True,
                      exclude_ambiguous=False) -> str:
    """
    Cryptographically secure password generation.
    Algorithm:
      1. Guarantee ≥1 char from every enabled class (policy compliance).
      2. Fill remaining slots from full pool.
      3. Shuffle with secrets.SystemRandom (OS entropy, not Mersenne Twister).
    String built with ''.join(list) → O(N), not O(N²) concatenation.
    """
    pool = build_pool(use_lower, use_upper, use_digits, use_symbols, exclude_ambiguous)
    if not pool:
        raise ValueError("At least one character class must be selected.")

    guaranteed = []
    if use_lower and LOWERCASE:
        candidates = [c for c in LOWERCASE if c not in (AMBIGUOUS if exclude_ambiguous else set())]
        guaranteed.append(secrets.choice(candidates))
    if use_upper and UPPERCASE:
        candidates = [c for c in UPPERCASE if c not in (AMBIGUOUS if exclude_ambiguous else set())]
        guaranteed.append(secrets.choice(candidates))
    if use_digits and DIGITS:
        candidates = [c for c in DIGITS if c not in (AMBIGUOUS if exclude_ambiguous else set())]
        guaranteed.append(secrets.choice(candidates))
    if use_symbols:
        guaranteed.append(secrets.choice(SYMBOLS))

    guaranteed = guaranteed[:length]
    filler     = [secrets.choice(pool) for _ in range(length - len(guaranteed))]
    combined   = guaranteed + filler
    secrets.SystemRandom().shuffle(combined)
    return "".join(combined)          # O(N) join — not O(N²) +=


def generate_passphrase(word_count: int = 4, separator: str = "-",
                        capitalise: bool = True, append_digit: bool = True) -> str:
    """
    Diceware-style passphrase: easier to remember, harder to crack.
    Example: Maple-River-Forge-Eagle-7
    Entropy ≈ word_count × log₂(len(WORDLIST))
    """
    words = [secrets.choice(WORDLIST) for _ in range(word_count)]
    if capitalise:
        words = [w.capitalize() for w in words]
    phrase = separator.join(words)
    if append_digit:
        phrase += separator + str(secrets.randbelow(100))
    return phrase




def calculate_entropy(length: int, pool_size: int) -> float:
    """Shannon entropy: E = L × log₂(R)"""
    if pool_size <= 0 or length <= 0: return 0.0
    return length * math.log2(pool_size)

def classify_strength(entropy: float) -> tuple:
    if entropy < 28:  return "Very Weak",  RED("🔴"),    RED
    if entropy < 40:  return "Weak",        RED("🟠"),    RED
    if entropy < 60:  return "Moderate",    YELLOW("🟡"), YELLOW
    if entropy < 100: return "Strong",      GREEN("🟢"),  GREEN
    return               "Very Strong", GREEN("🟢🟢"), GREEN

def estimate_crack_time(entropy: float) -> str:
    """At 10 billion guesses/second (high-end GPU cluster)."""
    GPS  = 10_000_000_000
    secs = (2 ** entropy) / GPS
    if secs < 1:              return GREEN("< 1 second")
    if secs < 60:             return RED(f"{secs:.0f} seconds")
    if secs < 3600:           return RED(f"{secs/60:.0f} minutes")
    if secs < 86400:          return YELLOW(f"{secs/3600:.1f} hours")
    if secs < 31_536_000:     return YELLOW(f"{secs/86400:.0f} days")
    if secs < 3_153_600_000:  return GREEN(f"{secs/31_536_000:.0f} years")
    return                         GREEN(f"{secs/3_153_600_000:.2e} centuries")

def pattern_check(password: str) -> list:
    """Detect common weak patterns — returns list of warnings."""
    warnings = []
    p_lower  = password.lower()
    for walk in KEYBOARD_WALKS:
        if walk in p_lower:
            warnings.append(f"keyboard walk detected: '{walk}'")
    if len(set(password)) < len(password) * 0.5:
        warnings.append("many repeated characters")
    if p_lower in [w.lower() for w in WORDLIST]:
        warnings.append("single dictionary word")
    return warnings

HISTORY_FILE = "password_history.json"

def load_history() -> list:
    if not os.path.exists(HISTORY_FILE): return []
    with open(HISTORY_FILE) as f: return json.load(f)

def save_history(record: dict) -> None:
    history = load_history()
    history.append(record)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history[-50:], f, indent=2)   # keep last 50




BANNER = """
╔══════════════════════════════════════════════════════╗
║   🔐  VaultForge  ·  DecodeLabs Internship 2026    ║
║       Chittem Gowri  ·  Enterprise Password Engine  ║
╚══════════════════════════════════════════════════════╝"""

MENU = """
  ┌─ PASSWORD ENGINE ─────────────────────────────────┐
  │  [1] Quick generate        [5] Batch generate     │
  │  [2] Custom configuration  [6] Analyse a password │
  │  [3] Passphrase mode       [7] View history       │
  │  [4] Password policy test  [0] Exit               │
  └────────────────────────────────────────────────────┘"""


def print_report(password: str, pool_size: int, label: str = "GENERATED PASSWORD"):
    length  = len(password)
    entropy = calculate_entropy(length, pool_size)
    name, icon, color = classify_strength(entropy)
    crack   = estimate_crack_time(entropy)
    bar_f   = min(int(entropy / 5), 28)
    bar     = color("█") * bar_f + DIM("░") * (28 - bar_f)

    warnings = pattern_check(password)
    warn_str = ("\n  " + "\n  ".join(RED(f"  ⚠ {w}") for w in warnings)) if warnings else ""

    nist_ok  = GREEN("✔ PASS") if length >= NIST_MIN    else RED("✗ FAIL")
    sec_ok   = GREEN("✔ PASS") if length >= NIST_SECURE else YELLOW("Increase length")

    print(f"""
  ╔══════════════════════════════════════════════╗
  ║  {BOLD(label):<44}║
  ║                                              ║
  ║  {CYAN(password[:44]):<44}║
  ╚══════════════════════════════════════════════╝

  {BOLD('Security Analysis')}  (E = L × log₂ R)
  ──────────────────────────────────────────
  Length       : {length} characters
  Pool size    : {pool_size} symbols
  Entropy      : {BOLD(f'{entropy:.1f} bits')}
  Strength     : {icon} {BOLD(name)}
  Bar          : [{bar}]
  Crack time   : {crack}
  ──────────────────────────────────────────
  NIST SP 800-63-4 (min 8)  : {nist_ok}
  High-security (16+)       : {sec_ok}{warn_str}
""")




def _get_length(prompt=None) -> int:
    msg = prompt or f"  Length (min {NIST_MIN}, recommended {NIST_SECURE}+): "
    while True:
        try:
            raw = input(msg).strip()
            n   = int(raw)
            if n < NIST_MIN:  print(RED(f"  ✗ NIST minimum is {NIST_MIN}.")); continue
            if n > 256:       print(RED("  ✗ Maximum is 256.")); continue
            return n
        except ValueError:
            print(RED(f"  ✗ '{raw}' is not a valid integer."))

def _yn(prompt, default_yes=True) -> bool:
    hint = "[Y/n]" if default_yes else "[y/N]"
    raw  = input(f"  {prompt} {hint}: ").strip().lower()
    return (raw != "n") if default_yes else (raw == "y")

def _get_options() -> dict:
    print("\n  Character classes:")
    return {
        "use_lower":           _yn("Lowercase letters?"),
        "use_upper":           _yn("Uppercase letters?"),
        "use_digits":          _yn("Digits?"),
        "use_symbols":         _yn("Symbols (!@#...)?", default_yes=False),
        "exclude_ambiguous":   _yn("Exclude ambiguous chars (0,O,1,l,I)?", default_yes=False),
    }


def main():
    print(CYAN(BANNER))

    while True:
        print(MENU)
        choice = input("\n  Enter choice: ").strip()

        # ── [1] Quick generate ──────────────────
        if choice == "1":
            length   = _get_length()
            pool     = build_pool()
            password = generate_password(length)
            print_report(password, len(pool))
            save_history({"type": "password", "length": length,
                          "entropy": round(calculate_entropy(length, len(pool)), 1),
                          "date": datetime.now().strftime("%Y-%m-%d %H:%M")})

        # ── [2] Custom configuration ────────────
        elif choice == "2":
            length = _get_length()
            opts   = _get_options()
            if not any(opts[k] for k in ["use_lower","use_upper","use_digits","use_symbols"]):
                print(RED("  ✗ At least one character class required.")); continue
            pool     = build_pool(**opts)
            password = generate_password(length, **opts)
            print_report(password, len(pool), "CUSTOM PASSWORD")
            save_history({"type": "custom", "length": length,
                          "entropy": round(calculate_entropy(length, len(pool)), 1),
                          "date": datetime.now().strftime("%Y-%m-%d %H:%M")})

        # ── [3] Passphrase mode ─────────────────
        elif choice == "3":
            try:
                words = int(input("  Number of words [4–8] (default=4): ").strip() or "4")
                if not 2 <= words <= 8:
                    print(RED("  ✗ Use 2–8 words.")); continue
            except ValueError:
                words = 4
            sep       = input("  Separator (default '-'): ").strip() or "-"
            cap       = _yn("Capitalise words?")
            digit     = _yn("Append random digit?")
            phrase    = generate_passphrase(words, sep, cap, digit)
            pool_size = len(WORDLIST)
            entropy   = words * math.log2(pool_size) + (math.log2(100) if digit else 0)
            name, icon, color = classify_strength(entropy)
            crack     = estimate_crack_time(entropy)

            print(f"""
  ╔══════════════════════════════════════════════╗
  ║  PASSPHRASE                                  ║
  ║  {CYAN(phrase[:44]):<44}║
  ╚══════════════════════════════════════════════╝

  Word count   : {words} from {pool_size}-word list
  Entropy      : {BOLD(f'{entropy:.1f} bits')}
  Strength     : {icon} {BOLD(name)}
  Crack time   : {crack}
  Tip          : {DIM('Easier to remember than random characters!')}
""")
            save_history({"type": "passphrase", "words": words,
                          "entropy": round(entropy, 1),
                          "date": datetime.now().strftime("%Y-%m-%d %H:%M")})

        # ── [4] Policy test ─────────────────────
        elif choice == "4":
            print(f"\n  {BOLD('Password Policy Tester')}")
            print(DIM("  Enter a password to check against NIST and security rules."))
            password = input("  Password: ")
            pool_size = len(set(password))

            checks = [
                ("Min 8 characters",       len(password) >= 8),
                ("Min 12 characters",      len(password) >= 12),
                ("Min 16 characters",      len(password) >= 16),
                ("Has lowercase",          any(c in LOWERCASE for c in password)),
                ("Has uppercase",          any(c in UPPERCASE for c in password)),
                ("Has digit",              any(c in DIGITS    for c in password)),
                ("Has special character",  any(c in SYMBOLS   for c in password)),
                ("No keyboard walk",       not any(w in password.lower() for w in KEYBOARD_WALKS)),
                ("Not a single word",      password.lower() not in [w.lower() for w in WORDLIST]),
            ]

            print(f"\n  {BOLD('Policy Checks:')}")
            for rule, passed in checks:
                icon = GREEN("✔") if passed else RED("✗")
                print(f"  {icon}  {rule}")

            entropy = calculate_entropy(len(password), max(pool_size, 10))
            name, icon, color = classify_strength(entropy)
            print(f"\n  Estimated entropy: {BOLD(f'{entropy:.1f} bits')} → {icon} {name}")
            print(f"  Crack time: {estimate_crack_time(entropy)}")

        # ── [5] Batch generate ──────────────────
        elif choice == "5":
            try:
                count  = int(input("  How many passwords?: ").strip())
                length = _get_length()
                pool   = build_pool()
                print(f"\n  {BOLD(f'── {count} Generated Passwords ──')}")
                for i in range(1, count + 1):
                    pw   = generate_password(length)
                    ent  = calculate_entropy(length, len(pool))
                    name, icon, _ = classify_strength(ent)
                    print(f"  {i:>3}. {CYAN(pw)}   {icon} {ent:.0f}bit  {DIM(name)}")
            except ValueError:
                print(RED("  ✗ Enter a valid number."))

        # ── [6] Analyse a password ───────────────
        elif choice == "6":
            password = input("\n  Enter password to analyse: ")
            pool_size = (len([c for c in string.ascii_lowercase if c in password] and LOWERCASE) +
                         len([c for c in string.ascii_uppercase if c in password] and UPPERCASE) +
                         len([c for c in string.digits          if c in password] and DIGITS)    +
                         len([c for c in string.punctuation     if c in password] and SYMBOLS))
            pool_size = max(pool_size, len(set(password)), 10)
            print_report(password, pool_size, "PASSWORD ANALYSIS")

        # ── [7] History ─────────────────────────
        elif choice == "7":
            history = load_history()
            if not history:
                print(DIM("\n  No history found.")); continue
            print(f"\n  {BOLD(f'── Last {len(history)} Generated ──')}")
            for h in history:
                t   = h.get("type", "pw")
                ent = h.get("entropy", 0)
                name, icon, _ = classify_strength(ent)
                if t == "passphrase":
                    detail = f"{h.get('words',4)} words"
                else:
                    detail = f"len={h.get('length',0)}"
                print(f"  {h['date']}  {t:<10}  {detail:<10}  {ent:>6.1f}bit  {icon} {DIM(name)}")

        elif choice == "0":
            print(GREEN("\n  Stay secure! 🔐  Goodbye!\n")); break

        else:
            print(RED("  ✗ Invalid option."))

if __name__ == "__main__":
    main()
