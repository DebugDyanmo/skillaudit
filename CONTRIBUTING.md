# Contributing to skillaudit

Thanks for helping! The easiest way to contribute is **adding or improving a detection rule**.

## Add a rule in 5 minutes

1. Open `src/skillaudit/rules.py` and add an entry to `RULES` with a new `SAxxx` id.
2. Add a test in `tests/test_scanner.py` showing one line that should match and one that should not.
3. Run `pip install -e . pytest && pytest`.
4. Open a pull request describing the real-world attack the rule catches.

## Guidelines

- Prefer **low false positives**. A noisy tool gets uninstalled.
- Every rule needs a short, actionable `advice` message.
- Keep the core dependency-free (standard library only).

Look for issues labeled `good first issue` to get started.
