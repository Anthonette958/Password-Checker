#!/usr/bin/env python3
"""Password Strength Analyzer and Entropy Calculator (Linux CLI)."""

import argparse
import getpass
import math
import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

try:
    from zxcvbn import zxcvbn as _zxcvbn
except Exception:
    _zxcvbn = None

TITLE = "Password Strength Analyzer & Entropy Calculator"
VERSION = "1.0.0"

LOWER_POOL = 26
UPPER_POOL = 26
DIGIT_POOL = 10
SPECIAL_POOL = 32

PREDICTABLE_WORDS = {
    "password", "passw0rd", "admin", "administrator", "welcome", "letmein",
    "qwerty", "iloveyou", "monkey", "dragon", "football", "baseball",
    "abc123", "123456", "login", "master", "hello", "freedom", "trustno1",
    "sunshine", "princess", "shadow", "superman", "batman", "access",
}

SUBSTITUTIONS = {
    "a": "a", "@": "a", "4": "a",
    "s": "s", "$": "s", "5": "s",
    "e": "e", "3": "e",
    "i": "i", "1": "i", "!": "i", "|": "i",
    "l": "l", "1": "l",
    "o": "o", "0": "o",
    "t": "t", "7": "t",
    "g": "g", "9": "g",
    "b": "b", "8": "b",
    "z": "z", "2": "z",
}

KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")


def load_wordlist(path: str = None) -> Set[str]:
    """Load a local wordlist file into a set of lowercased passwords.

    Returns an empty set if the file is missing or unreadable.
    """
    candidates: List[Path] = []
    if path:
        candidates.append(Path(path))
    else:
        here = Path(__file__).resolve().parent
        candidates.append(here / "wordlists" / "common_passwords.txt")
        candidates.append(here / "common_passwords.txt")

    for candidate in candidates:
        try:
            if candidate.is_file():
                words: Set[str] = set()
                with candidate.open("r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        w = line.strip()
                        if w and not w.startswith("#"):
                            words.add(w.lower())
                return words
        except (OSError, IOError):
            continue
    return set()


def char_pool_size(password: str) -> int:
    """Return the assumed character pool size based on categories present."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += LOWER_POOL
    if re.search(r"[A-Z]", password):
        pool += UPPER_POOL
    if re.search(r"\d", password):
        pool += DIGIT_POOL
    if re.search(r"[^A-Za-z0-9]", password):
        pool += SPECIAL_POOL
    return pool


def theoretical_entropy(password: str) -> float:
    """Compute theoretical entropy H = L * log2(R) in bits."""
    length = len(password)
    pool = char_pool_size(password)
    if length == 0 or pool <= 0:
        return 0.0
    return length * math.log2(pool)
def normalize_substitutions(password: str) -> str:
    """Reverse common leetspeak substitutions to a lowercase base string."""
    return "".join(SUBSTITUTIONS.get(ch.lower(), ch.lower()) for ch in password)


def detect_repeated(password: str) -> List[str]:
    """Detect runs of the same character of length >= 3."""
    return list(dict.fromkeys(re.findall(r"(.)\1{2,}", password)))


def detect_sequences(password: str) -> List[str]:
    """Detect keyboard/alphabet/numeric sequences of length >= 3."""
    found: List[str] = []
    low = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 2):
            tri = row[i:i + 3]
            if tri in low and tri not in found:
                found.append(tri)
    for i in range(len(password) - 2):
        a, b, c = ord(password[i]), ord(password[i + 1]), ord(password[i + 2])
        if (b - a == 1 and c - b == 1) or (a - b == 1 and b - c == 1):
            tri = password[i:i + 3]
            if tri not in found:
                found.append(tri)
    return found


def detect_predictable_words(password: str, wordlist: Set[str]) -> List[str]:
    """Find common/dictionary words contained in the password."""
    found: List[str] = []
    low = password.lower()
    candidates = set(PREDICTABLE_WORDS) | set(w for w in wordlist if len(w) >= 4)
    for word in candidates:
        if word and word in low:
            found.append(word)
    norm = normalize_substitutions(password)
    if norm != low:
        for word in candidates:
            if word and word in norm and word not in found:
                found.append(word + " (via substitution)")
    return sorted(set(found))


def has_substitutions(password: str) -> bool:
    """Whether the password uses common leetspeak substitutions."""
    special = set("@$013789!|")
    return any(ch in special for ch in password) and any(c.isalpha() for c in password)


def is_common_password(password: str, wordlist: Set[str]) -> Tuple[bool, str]:
    """Check whether password (or its normalized form) is in the wordlist."""
    low = password.lower()
    if low in wordlist:
        return True, password
    norm = normalize_substitutions(password)
    if norm in wordlist and norm != low:
        return True, norm
    return False, ""


def run_zxcvbn(password: str) -> dict:
    if _zxcvbn is None:
        return {
            "score": 0,
            "crack_times_display": {},
            "feedback": {"warning": "zxcvbn unavailable", "suggestions": []},
            "sequence": [],
        }
    try:
        return _zxcvbn(password)
    except Exception as exc:
        return {
            "score": 0,
            "crack_times_display": {},
            "feedback": {"warning": str(exc), "suggestions": []},
            "sequence": [],
        }


def strength_label(score: int) -> str:
    labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
    if score < 0:
        score = 0
    if score > 4:
        score = 4
    return labels[score]

def assess(password: str, wordlist: Set[str]) -> dict:
    """Perform full assessment and return a structured result dict."""
    zx = run_zxcvbn(password)
    common, matched = is_common_password(password, wordlist)
    pool = char_pool_size(password)
    entropy = theoretical_entropy(password)
    repeated = detect_repeated(password)
    sequences = detect_sequences(password)
    predictable = detect_predictable_words(password, wordlist)
    subs = has_substitutions(password)

    if common:
        rating = "Very Weak"
    else:
        rating = strength_label(zx.get("score", 0))
    if len(password) == 0:
        rating = "Very Weak"
    elif len(password) < 6:
        if rating not in ("Very Weak",):
            rating = "Very Weak"
    elif len(password) < 8:
        if rating in ("Strong", "Very Strong", "Fair"):
            rating = "Weak"

    categories = {
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digits": bool(re.search(r"\d", password)),
        "special": bool(re.search(r"[^A-Za-z0-9]", password)),
    }

    recs: List[str] = []
    if common:
        recs.append("This password appears in a common-password list; choose a unique password.")
    if len(password) < 12:
        recs.append("Use a longer password (12-16+ characters) or a multi-word passphrase.")
    missing = [name for name, ok in categories.items() if not ok]
    if missing:
        recs.append("Add missing character types: " + ", ".join(missing) + ".")
    if repeated:
        recs.append("Avoid repeated characters (e.g., 'aaa').")
    if sequences:
        recs.append("Avoid predictable sequences (e.g., 'abc', '123', keyboard runs).")
    if subs:
        recs.append("Avoid common substitutions (leetspeak like '@' for 'a'); they are easily guessed.")
    if predictable:
        recs.append("Avoid dictionary words and personal information.")
    fb = zx.get("feedback", {}) or {}
    warning = fb.get("warning")
    if warning:
        recs.append("zxcvbn: " + warning)
    for s in fb.get("suggestions", []) or []:
        recs.append("zxcvbn: " + s)
    if not recs:
        recs.append("Password looks strong. Keep it unique and store it in a password manager.")
    recs.append("Do not reuse this password across multiple accounts.")

    return {
        "password_length": len(password),
        "categories": categories,
        "char_pool": pool,
        "entropy_bits": round(entropy, 2),
        "common_password": common,
        "common_match": matched,
        "wordlist_size": len(wordlist),
        "repeated": repeated,
        "sequences": sequences,
        "predictable_words": predictable,
        "substitutions": subs,
        "zxcvbn_score": zx.get("score", 0),
        "zxcvbn_crack_times": zx.get("crack_times_display", {}),
        "zxcvbn_feedback": fb,
        "rating": rating,
        "recommendations": recs,
    }

def print_report(result: dict) -> None:
    print()
    print("=" * 60)
    print(f"{TITLE}  v{VERSION}")
    print("=" * 60)
    print(f"Length:            {result['password_length']}")
    cats = result["categories"]
    print(
        "Character types:   "
        f"lower={cats['lowercase']} upper={cats['uppercase']} "
        f"digits={cats['digits']} special={cats['special']}"
    )
    print(f"Assumed pool (R):  {result['char_pool']}")
    print(f"Theoretical entropy H = L x log2(R): {result['entropy_bits']} bits")
    print()
    print(f"Common password:   {'YES (match found)' if result['common_password'] else 'No'}")
    if result["common_password"] and result["common_match"]:
        print(f"  Matched entry: {result['common_match']}")
    print(f"Wordlist entries:  {result['wordlist_size']}")
    print()
    print(f"Repeated chars:    {', '.join(result['repeated']) if result['repeated'] else 'None detected'}")
    print(f"Sequences:         {', '.join(result['sequences']) if result['sequences'] else 'None detected'}")
    print(f"Substitutions:     {'Yes' if result['substitutions'] else 'No'}")
    print(f"Predictable words: {', '.join(result['predictable_words']) if result['predictable_words'] else 'None detected'}")
    print()
    print(f"zxcvbn score:      {result['zxcvbn_score']} / 4")
    ct = result["zxcvbn_crack_times"]
    if ct:
        print("Estimated crack times:")
        for k, v in ct.items():
            print(f"  {k}: {v}")
    fb = result["zxcvbn_feedback"] or {}
    if fb.get("warning"):
        print(f"zxcvbn warning:    {fb['warning']}")
    print()
    print(f"Strength rating:   {result['rating']}")
    print("-" * 60)
    print("Recommendations:")
    for r in result["recommendations"]:
        print(f"  - {r}")
    print("-" * 60)
    print("Note: Theoretical entropy assumes independent, uniformly random")
    print("characters from the detected pool. Real guessability (zxcvbn)")
    print("also accounts for patterns, dictionaries, and reuse.")
    print("=" * 60)
    print()

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tricky",
        description=f"{TITLE} v{VERSION} - Linux CLI password strength analyzer.",
    )
    parser.add_argument("-w", "--wordlist", metavar="PATH",
                        help="Path to a custom local wordlist file.")
    parser.add_argument("-V", "--version", action="version",
                        version=f"{TITLE} {VERSION}")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    print(f"{TITLE} v{VERSION}")
    print("Your password will not be displayed or stored.")
    try:
        password = getpass.getpass("Enter password to analyze: ")
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.", file=sys.stderr)
        return 130

    if password == "":
        print("Error: empty password provided.", file=sys.stderr)
        return 2

    wordlist = load_wordlist(args.wordlist)
    result = assess(password, wordlist)
    print_report(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

