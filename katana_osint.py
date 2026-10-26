#!/usr/bin/env python3
"""Foxtail Katana OSINT: bounded public lookups with case evidence.

Original integration; no Octopus code or bundled scanning tools are imported.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid

VERSION = "1.0"
TIMEOUT = 12
MAX_BYTES = 4 * 1024 * 1024
UA = "Foxtail-Katana-OSINT/" + VERSION
PLATFORMS = {
    "GitHub": "https://github.com/{username}",
    "GitLab": "https://gitlab.com/{username}",
    "DEV Community": "https://dev.to/{username}",
    "Reddit": "https://www.reddit.com/user/{username}/",
    "X": "https://x.com/{username}",
    "Instagram": "https://www.instagram.com/{username}/",
    "Facebook": "https://www.facebook.com/{username}/",
    "LinkedIn": "https://www.linkedin.com/in/{username}/",
    "Medium": "https://medium.com/@{username}",
    "Twitch": "https://www.twitch.tv/{username}",
    "YouTube": "https://www.youtube.com/@{username}",
}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean_text(value):
    # Provider content must never inject terminal escapes or control sequences.
    return "".join(c for c in str(value) if not unicodedata.category(c).startswith("C") or c in "\n\t")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_json(url):
    """Capture provenance; rate limits/HTML/redirects stay unknown, never matches."""
    source = {"url": url, "retrieved_at_utc": utc_now(), "http_status": None}
    if urllib.parse.urlsplit(url).scheme != "https":
        source["error"] = "Only HTTPS source URLs are supported."
        return None, source
    request = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        opener = urllib.request.build_opener(NoRedirect())
        with opener.open(request, timeout=TIMEOUT) as response:
            source["http_status"] = response.status
            # An overall deadline and size cap also bound slow/chunked responses.
            deadline = time.monotonic() + TIMEOUT
            body = bytearray()
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError("Source response exceeded the read deadline.")
                chunk = response.read1(min(65536, MAX_BYTES + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > MAX_BYTES:
                    raise ValueError("Source response exceeded the 4 MiB limit; results were not truncated silently.")
            source["response_sha256"] = hashlib.sha256(body).hexdigest()
            source["response_bytes"] = len(body)
            data = json.loads(body)
            # Keep the provider evidence as well as the normalized observations.
            source["response_json"] = data
            return data, source
    except urllib.error.HTTPError as exc:
        source["http_status"] = exc.code
        source["error"] = "HTTP " + str(exc.code)
        if exc.headers.get("Retry-After"):
            source["retry_after"] = exc.headers["Retry-After"]
    except Exception as exc:
        source["error"] = clean_text(exc)
    return None, source


def username_lookup(query, fetch=fetch_json):
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", query):
        raise ValueError("Use a username of 1–80 letters, digits, dots, underscores or hyphens; enter no URL or @ prefix.")
    encoded = urllib.parse.quote(query, safe="")
    observations, sources = [], []
    for platform, template in PLATFORMS.items():
        item = {"platform": platform, "profile_url": template.format(username=encoded),
                "status": "unverified", "note": "Candidate link only; open it to check the public profile."}
        endpoint = None
        if platform == "GitHub" and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", query) and "--" not in query:
            endpoint = "https://api.github.com/users/" + encoded
        elif platform == "GitLab":
            endpoint = "https://gitlab.com/api/v4/users?username=" + encoded
        elif platform == "DEV Community" and re.fullmatch(r"[A-Za-z0-9_]{3,30}", query):
            endpoint = "https://dev.to/api/users/by_username?url=" + encoded
        if endpoint:
            data, source = fetch(endpoint)
            sources.append(source)
            item["source_url"] = endpoint
            item["checked_at_utc"] = source["retrieved_at_utc"]
            item["http_status"] = source.get("http_status")
            public_match = False
            valid_response = False
            if source.get("http_status") == 200:
                if platform == "GitLab" and isinstance(data, list):
                    valid_response = all(isinstance(row, dict) and isinstance(row.get("username"), str) for row in data)
                    public_match = valid_response and any(row["username"].casefold() == query.casefold() for row in data)
                elif isinstance(data, dict):
                    field = "login" if platform == "GitHub" else "username"
                    valid_response = isinstance(data.get(field), str)
                    public_match = valid_response and data[field].casefold() == query.casefold()
            if public_match:
                item.update(status="public_profile", note="Provider API returned this exact username. Ownership/identity is not established.")
            elif source.get("http_status") == 404 or (platform == "GitLab" and valid_response and not data):
                item.update(status="not_found_public", note="No public profile returned by this provider at lookup time.")
            else:
                item["note"] = "Unverified: " + source.get("error", "provider response did not establish an exact username match.")
        observations.append(item)
    return observations, sources, [
        "A matching username does not establish that accounts belong to the same person.",
        "Candidate links are not confirmed matches. Blocks, rate limits, login screens and unexpected responses remain unverified.",
    ]


def phone_lookup(query, region="US"):
    try:
        import phonenumbers as pn
        from phonenumbers import carrier, geocoder, timezone as phone_timezone
    except ImportError as exc:
        raise RuntimeError("Phone metadata support is unavailable. Repair Katana's OSINT environment before retrying.") from exc
    region = region.strip().upper()
    if region not in pn.SUPPORTED_REGIONS:
        raise ValueError("Choose a supported two-letter phone region, such as US or GB.")
    if len(query) > 80:
        raise ValueError("Phone number is too long.")
    try:
        number = pn.parse(query, None if query.startswith("+") else region)
    except pn.NumberParseException as exc:
        raise ValueError("Could not parse the phone number: " + str(exc)) from exc
    values = {
        "e164": pn.format_number(number, pn.PhoneNumberFormat.E164),
        "international": pn.format_number(number, pn.PhoneNumberFormat.INTERNATIONAL),
        "national": pn.format_number(number, pn.PhoneNumberFormat.NATIONAL),
        "default_region": region, "region_code": pn.region_code_for_number(number),
        "possible_format": pn.is_possible_number(number), "valid_numbering_plan": pn.is_valid_number(number),
        "number_type": pn.PhoneNumberType.to_string(pn.number_type(number)),
        "numbering_plan_region": geocoder.description_for_number(number, "en"),
        "original_carrier_metadata": carrier.name_for_number(number, "en"),
        "timezones": list(phone_timezone.time_zones_for_number(number)),
    }
    source = {"url": "https://github.com/daviddrysdale/python-phonenumbers", "retrieved_at_utc": utc_now(),
              "method": "offline numbering-plan metadata", "library_version": pn.__version__}
    return [values], [source], [
        "Numbering-plan validation does not prove a number is assigned, active, or owned by any particular person.",
        "Region/timezone describe numbering metadata, not live location. Carrier metadata may predate number portability.",
        "This lookup runs offline and sends no phone number to an external service.",
    ]


def reverse_dns(ip):
    # DNS calls can hang outside Python socket timeouts; bound a separate process.
    code = "import json,socket,sys; print(json.dumps(socket.gethostbyaddr(sys.argv[1])[0]))"
    try:
        result = subprocess.run([sys.executable, "-c", code, ip], capture_output=True, text=True, timeout=4)
        if result.returncode == 0:
            return {"hostname": json.loads(result.stdout), "status": "returned"}
        return {"status": "unavailable"}
    except (subprocess.TimeoutExpired, ValueError, OSError):
        return {"status": "unavailable"}


def ip_lookup(query, fetch=fetch_json, resolver=reverse_dns):
    if "%" in query:
        raise ValueError("Enter an IPv4 or IPv6 address without an interface zone suffix.")
    ip = ipaddress.ip_address(query)
    values = {"ip": str(ip), "version": ip.version, "global": ip.is_global,
              "private": ip.is_private, "loopback": ip.is_loopback, "multicast": ip.is_multicast,
              "reserved": ip.is_reserved, "link_local": ip.is_link_local}
    sources = [{"method": "local IP classification", "retrieved_at_utc": utc_now(), "python_version": sys.version.split()[0]}]
    if ip.is_global and not ip.is_multicast:
        values["reverse_dns"] = resolver(str(ip))
        sources.append({"method": "system resolver PTR lookup", "query": str(ip), "retrieved_at_utc": utc_now()})
        endpoint = "https://ipwho.is/" + urllib.parse.quote(str(ip), safe="")
        data, source = fetch(endpoint)
        sources.append(source)
        matches = False
        if isinstance(data, dict) and data.get("success") is True:
            try:
                matches = ipaddress.ip_address(data.get("ip", "")) == ip
            except ValueError:
                pass
        if matches and source.get("http_status") == 200:
            for key in ("country", "region", "city", "latitude", "longitude", "connection", "timezone"):
                values[key] = data.get(key)
            values["public_metadata_status"] = "returned"
        else:
            values["public_metadata_status"] = "unavailable"
            source.setdefault("error", "Provider did not return metadata for the exact queried IP.")
            values["note"] = source["error"]
    else:
        values["public_metadata_status"] = "skipped_nonpublic"
        values["note"] = "Nonpublic/special-purpose IP: no external lookup was made."
    return [values], sources, [
        "IP geolocation is approximate; it can locate a provider, VPN or network gateway rather than a person/device.",
        "PTR names and provider metadata are observations, not verified ownership or device location.",
    ]


def normalize_domain(value):
    domain = value.strip().rstrip(".").lower().encode("idna").decode("ascii")
    if len(domain) > 253 or "." not in domain:
        raise ValueError("Enter a domain name, such as example.com; no URL, path or wildcard.")
    labels = domain.split(".")
    if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in labels):
        raise ValueError("Invalid domain name. Enter no URL, path, port or wildcard.")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError("Enter a domain name, not an IP address.")


def subdomain_lookup(query, fetch=fetch_json):
    domain = normalize_domain(query)
    endpoint = "https://crt.sh/?" + urllib.parse.urlencode({"q": "%." + domain, "output": "json"})
    data, source = fetch(endpoint)
    sources = [source]
    fallback = False
    if source.get("http_status") != 200 or not isinstance(data, list):
        source.setdefault("error", "Certificate-log provider did not return a JSON list.")
        # Cert Spotter provides an independent index of unexpired issuances.
        # Pagination is bounded and any incomplete traversal is stated explicitly.
        fallback = True
        data = []
        after = None
        for page in range(3):
            params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
            if after:
                params["after"] = after
            url = "https://api.certspotter.com/v1/issuances?" + urllib.parse.urlencode(params)
            records, fallback_source = fetch(url)
            sources.append(fallback_source)
            if fallback_source.get("http_status") != 200 or not isinstance(records, list):
                fallback_source.setdefault("error", "Cert Spotter lookup unavailable; results may be incomplete.")
                break
            if not records:
                fallback_source["pagination"] = "complete"
                break
            for record in records:
                if not isinstance(record, dict) or not isinstance(record.get("dns_names"), list) or not all(isinstance(name, str) for name in record["dns_names"]):
                    fallback_source["error"] = "Malformed Cert Spotter rows; results may be incomplete."
                    continue
                identifier = str(record.get("id", ""))
                data.append({"name_value": "\n".join(record["dns_names"]),
                             "id": int(identifier) if re.fullmatch(r"[0-9]{1,30}", identifier) else None,
                             "_source_url": url})
            last_record = records[-1]
            next_id = str(last_record.get("id", "")) if isinstance(last_record, dict) else ""
            if not re.fullmatch(r"[0-9]{1,30}", next_id) or next_id == after:
                fallback_source["error"] = "Cert Spotter pagination cursor unavailable; results may be incomplete."
                break
            after = next_id
            if page == 2:
                fallback_source["error"] = "Stopped at the three-page limit; more certificate records may exist."
    names = {}
    malformed = 0
    for row in data:
        if not isinstance(row, dict) or not isinstance(row.get("name_value"), str):
            malformed += 1
            continue
        for name in row["name_value"].splitlines():
            wildcard = name.strip().startswith("*.")
            name = name.strip().removeprefix("*.")
            try:
                name = normalize_domain(name)
            except (ValueError, UnicodeError):
                continue
            if name != domain and not name.endswith("." + domain):
                continue
            item = names.setdefault(name, {"hostname": name, "status": "certificate_log_observation", "wildcard_observed": False, "certificate_ids": [], "source_urls": []})
            item["wildcard_observed"] |= wildcard
            row_source = row.get("_source_url", endpoint)
            if row_source not in item["source_urls"]:
                item["source_urls"].append(row_source)
            cert_id = row.get("id")
            if isinstance(cert_id, int) and cert_id not in item["certificate_ids"]:
                item["certificate_ids"].append(cert_id)
    if malformed:
        source["error"] = f"Provider returned {malformed} malformed rows; results may be incomplete."
    limits = [
        "Certificate logs can contain historical names. A listed name does not prove a current/live host or current ownership.",
        "Wildcard certificates identify a namespace, not every individual host. No discovered hosts were contacted.",
        "This is a public certificate index, not an exhaustive inventory; an empty list is not proof of absence.",
    ]
    if fallback:
        limits.append("crt.sh was unavailable. Cert Spotter fallback covers unexpired issuances only and is limited to three pages per lookup.")
    if not data and any(item.get("error") for item in sources):
        limits.append("No certificate observations returned; check source errors before drawing conclusions.")
    return sorted(names.values(), key=lambda row: row["hostname"]), sources, limits


def render_report(report):
    lines = ["# Foxtail Katana OSINT", "", "Lookup: " + report["kind"], "Query: " + clean_text(report["query"]),
             "Case: " + clean_text(report["case_dir"]), "Collected (UTC): " + report["started_at_utc"],
             "Status: " + report["status"], ""]
    if report.get("error"):
        lines += ["Error: " + clean_text(report["error"]), ""]
    lines += ["## Interpretation", ""] + ["- " + item for item in report["limitations"]]
    lines += ["", "## Observations", ""]
    for row in report["observations"]:
        for key, value in row.items():
            lines.append(clean_text(key) + ": " + clean_text(json.dumps(value, ensure_ascii=False)))
        lines.append("")
    if not report["observations"]:
        lines += ["No observations returned. Check lookup status and sources before drawing conclusions.", ""]
    lines += ["## Sources", ""]
    for source in report["sources"]:
        for key, value in source.items():
            if key != "response_json":
                lines.append(clean_text(key) + ": " + clean_text(value))
        lines.append("")
    lines += ["Raw provider JSON, when available, is preserved in the companion JSON evidence file.", ""]
    return "\n".join(lines)


def save_report(report, case_dir):
    # Existing case is required. Do not silently create evidence in a wrong case/root.
    if not case_dir.is_dir():
        raise ValueError("Case folder is missing. Set/open a case in Katana first.")
    folder = case_dir / "osint"
    folder.mkdir(exist_ok=True)
    slug = report["kind"] + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8]
    json_path, text_path = folder / (slug + ".json"), folder / (slug + ".md")
    # Per-file exclusive creation avoids overwriting earlier case evidence.
    for path, content in ((json_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n"), (text_path, render_report(report))):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(content)
    return json_path, text_path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("username", "phone", "ip", "subdomains"))
    parser.add_argument("query")
    parser.add_argument("--case-dir", type=Path, required=True)
    parser.add_argument("--region", default="US")
    args = parser.parse_args(argv)
    query = args.query.strip()
    report = {"schema_version": 1, "tool": "Foxtail Katana OSINT", "tool_version": VERSION,
              "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "kind": args.kind, "query": query, "case_dir": str(args.case_dir.resolve()),
              "started_at_utc": utc_now(), "status": "complete", "observations": [], "sources": [], "limitations": []}
    try:
        if not args.case_dir.is_dir():
            raise ValueError("Case folder is missing. Set/open a case in Katana first.")
        if not query or len(query) > 253:
            raise ValueError("Enter a query of 1–253 characters.")
        if args.kind == "phone":
            result = phone_lookup(query, args.region)
        else:
            result = {"username": username_lookup, "ip": ip_lookup, "subdomains": subdomain_lookup}[args.kind](query)
        report["observations"], report["sources"], report["limitations"] = result
        if any(source.get("error") for source in report["sources"]):
            report["status"] = "partial" if report["observations"] else "unavailable"
        if args.kind == "username" and any(row.get("source_url") and row["status"] == "unverified" for row in report["observations"]):
            report["status"] = "partial"
        if args.kind == "ip" and report["observations"][0].get("public_metadata_status") == "unavailable":
            report["status"] = "partial"
    except KeyboardInterrupt:
        report.update(status="cancelled", error="Lookup interrupted; no conclusions can be drawn from incomplete results.")
    except Exception as exc:
        report.update(status="error", error=clean_text(exc))
    report["finished_at_utc"] = utc_now()
    try:
        paths = save_report(report, args.case_dir)
    except Exception as exc:
        print("Could not save OSINT evidence: " + clean_text(exc), file=sys.stderr)
        return 1
    print(render_report(report))
    print("Saved JSON: " + clean_text(paths[0]))
    print("Saved report: " + clean_text(paths[1]))
    return 0 if report["status"] in ("complete", "partial") else 1


if __name__ == "__main__":
    raise SystemExit(main())
