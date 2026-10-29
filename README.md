# Password Strength Analyzer & Entropy Calculator

Linux command-line tool (Python 3) that evaluates password strength,
estimates theoretical entropy, detects common passwords via a local
wordlist, and provides security recommendations.

## Requirements

- Python 3
- `zxcvbn` (`pip install zxcvbn`)

## Usage

```bash
chmod +x tricky.py
./tricky.py --help
./tricky.py
./tricky.py --wordlist /path/to/wordlist.txt
./tricky.py --version
```

### Extra predictable wordlist

Set `PREDICTABLE_WORDLIST` or edit `PREDICTABLE_WORDLIST_PATH` in `tricky.py`
to load additional words (length >= 4) treated as predictable:

```bash
PREDICTABLE_WORDLIST=/path/to/words.txt ./tricky.py
```

The password is read securely (not echoed). It is never stored or
uploaded.

## Features

- Strength rating: Very Weak, Weak, Fair, Strong, Very Strong
- Theoretical entropy: `H = L * log2(R)`
- Local common-password detection
- Character & pattern analysis (repeated chars, sequences, substitutions)
- Security recommendations
- zxcvbn guessability estimation

## Testing

```bash
python -m unittest discover -s tests
```
