<img src="assets/katana.png" alt="" width="86" align="right">

# Foxtail Katana OSINT

[![Checks](https://github.com/CDeSanto84/foxtail-katana-osint/actions/workflows/checks.yml/badge.svg)](https://github.com/CDeSanto84/foxtail-katana-osint/actions/workflows/checks.yml)

**Bounded public-source lookups with evidence and provenance.**

The standalone OSINT engine from the Foxtail Katana desktop workbench. It turns
username, phone, IP, and certificate-log lookups into JSON evidence and a
readable Markdown report, with timestamps, source URLs, response hashes, and
explicit limits on interpretation.

## What it does

- Username lookups that distinguish provider responses from unverified profile
  links; a shared username is not treated as proof of identity.
- Local phone-number parsing/validation through `phonenumbers`, with region
  context rather than claims about a subscriber or live location.
- Public IP metadata with optional reverse DNS context.
- Subdomain observations from public certificate indexes, with bounded fallback
  pagination and no follow-up probing of discovered hosts.
- HTTPS-only JSON requests, redirect refusal, response-size limits, and deadlines.
- Separate complete, partial, unavailable, error, and cancelled outcomes.
- Per-file exclusive report creation with owner-only permissions, preserving
  normalized observations and available raw provider responses.

**Status:** working CLI component, version 1.0. This repository publishes the
original lookup/report engine. The older GTK cockpit, its PIN gate, external
security-tool launchers, and private case output are not included. This is a
separate Foxtail project, not ProjectDiscovery's Katana crawler.

## Run

Requires Python 3.10+.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install --require-hashes -r requirements.lock
mkdir -p cases/example
python katana_osint.py subdomains example.com --case-dir cases/example
```

Other lookup kinds are `username`, `phone`, and `ip`. Phone lookups accept
`--region`, for example `--region US`. A case directory must already exist;
reports are stored in its `osint/` subdirectory. Case output is ignored by Git.
Public-source queries depend on provider availability and may be rate limited.

## Checks

```bash
python3 -m unittest -v test_osint.py
python3 -m py_compile katana_osint.py
```

The tests use mocked providers and temporary evidence directories. They cover
input validation, unavailable sources, incomplete results, certificate-name
filtering, evidence preservation, and output permissions.

## Interpretation

Certificate observations can be historical. A phone prefix is not a person's
current location. Username matches are leads, not identity verification. Source
failures remain visible in the report instead of being converted into negative
findings. Use the tool for research you are authorized to perform and respect
the relevant provider's access rules.
