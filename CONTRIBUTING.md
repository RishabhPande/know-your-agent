# Contributing to Know Your Agent

Thanks for helping improve Know Your Agent. Start with the README, which
documents the credential format, the API, and the demo.

## Running the checks

```bash
pip install -r requirements.txt
python -m pytest tests/ -q
```

Run the demo with `python demo.py` (see the README's Quickstart for the
expected output).

## Proposing a change

1. Fork the repo and create a branch for your change.
2. Make your change, add or update tests where it makes sense, and run the
   checks above.
3. Open a pull request describing what changed and why.

Please do not commit private keys or real credentials: demo keys are
generated in memory and discarded on exit (see the README's Security notes).
