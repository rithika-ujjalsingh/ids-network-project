# Contributing to IDS - Intrusion Detection System

Thanks for your interest in improving this project! 🙌

## How to Contribute

1. **Fork** the repository
2. **Create a branch** for your change:
```bash
   git checkout -b feature/your-feature-name
```
3. **Make your changes** — keep them focused and well-commented
4. **Test locally** before submitting:
```bash
   python -m venv venv && source venv/bin/activate
   pip install -r requirements.txt
   sudo venv/bin/python app.py
```
5. **Commit** with a clear message:
```bash
   git commit -m "feat: add ARP spoofing detection rule"
```
6. **Push** and open a **Pull Request** against `main`

## Code Style

- Follow [PEP 8](https://peps.python.org/pep-0008/) for Python code
- Add docstrings to new functions/classes
- Keep detection thresholds configurable (class constants in `ids_core.py`)

## Adding a New Detection Rule

1. Add a new `_check_<rule_name>()` method in `IDSEngine`
2. Define threshold/window constants at the top of the class
3. Call your check from `_process_packet()`
4. Log findings via `self._raise_alert(alert_type, src_ip, dst_ip, description, severity)`
5. Update the **Detection Logic** table in `README.md`

## Reporting Bugs / Requesting Features

Open a [GitHub Issue](../../issues) with:
- Clear title and description
- Steps to reproduce (for bugs)
- Expected vs actual behavior

## Reporting Security Issues

Please **do not** open a public issue for security vulnerabilities.
See [SECURITY.md](SECURITY.md) for responsible disclosure steps.
