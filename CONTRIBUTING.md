# Contributing

```bash
python3 -m venv .venv
.venv/bin/pip install -c requirements.lock -e ".[dev]"
.venv/bin/python tools/build_knowledge.py --check
.venv/bin/pytest
```

You need `tshark` 4.0 or newer. `tests/test_lab.py` also needs network namespaces.

- **Never attach a capture, key log or private key** to an issue or pull request. They can hold passwords, tokens and customer data. `tools/gen_samples.py` makes sample traffic.
- Cause text lives in `knowledge/`. Run `tools/build_knowledge.py` after a change and commit `knowledge.bin` too. Explanations must not call an AI model or an outside service.
- New interface text needs Turkish, German and Spanish in `knowledge/translations/`.
- Add each change to `RELEASE_NOTES.md`. Changes made on the same day are one minor version.
