# Testing the Network Path Tracing Toolkit

This project uses [pytest](https://docs.pytest.org/) for automated testing. The
suite currently covers the first two workflow steps (input validation and
gateway discovery) against both the protocol-oriented step logic and the API
adapter layer.

## Prerequisites

1. Create and activate a virtual environment (optional but recommended):

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install the project dependencies (includes pytest and responses for the
   tests):

   ```bash
   pip install -r requirements.txt
   ```

## Running the Tests

Execute the entire suite from the repository root:

```bash
pytest
```

Pytest will automatically discover tests under the `tests/` directory.

### Useful Pytest Flags

- Run a specific test file:

  ```bash
  pytest tests/test_steps.py
  ```

- Show captured log output:

  ```bash
  pytest -s
  ```

- Increase verbosity for more detailed output:

  ```bash
  pytest -vv
  ```

## Test Coverage Overview

- `tests/test_steps.py` exercises the step logic using in-memory data sources to
  simulate Nautobot ORM behaviour, covering success paths, fallback logic, and
  all failure scenarios.
- `tests/test_interfaces_api.py` uses the `responses` library to mock Nautobot’s
  REST API, ensuring the adapter issues the correct queries and parses device/
  interface details.

These tests run entirely offline; no live Nautobot instance is required.
