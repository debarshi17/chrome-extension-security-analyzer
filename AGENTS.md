# AGENTS.md

## Cursor Cloud specific instructions

### Project overview

Python-based browser extension security analyzer (Chrome/Edge/VSCode). Single-service architecture with CLI (`src/analyzer.py`) and FastAPI web UI (`web/app.py`).

### Running the application

- **Virtual environment**: `.venv` at the repo root. Activate with `source .venv/bin/activate`.
- **CLI**: `python src/analyzer.py <extension_id> --fast` (use `--fast` to skip VirusTotal API calls which require an API key).
- **Web UI**: `python web/app.py` starts FastAPI/Uvicorn on port 8000.
- **Config**: Copy `config.json.template` to `config.json` before running. VirusTotal API key is optional; use `--fast` or `--skip-vt` to bypass.

### Testing

- Tests require `PYTHONPATH=src:$PYTHONPATH` because `src/analyzer.py` uses bare imports like `from downloader import ...`.
- Run: `PYTHONPATH=src:$PYTHONPATH python -m pytest tests/test_fast_flag.py tests/test_skip_vt.py -v`
- `tests/test_fast_flag.py::test_parse_fast` has a pre-existing failure (missing required `extension_id` positional arg). The other 2 tests pass.
- `tests/regenerate_report.py` is a utility script, not a test; it requires a pre-existing JSON report file.

### Linting

- No project-specific linter config exists. Use `flake8 src/ web/ tests/ --max-line-length=120` for basic checks. Pre-existing style warnings are expected.

### Key caveats

- The `src/` directory uses bare module imports (not package-relative), so `src/` must be on `PYTHONPATH` or you must `cd src/` when running modules directly.
- Full end-to-end CLI analysis requires internet access to download extensions from Chrome Web Store.
- The web UI analysis runs in a background thread; progress is polled via `/status/{extension_id}`.
