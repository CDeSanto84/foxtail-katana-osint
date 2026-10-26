import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import katana_osint as app


def fixture(data=None, status=200, error=None):
    def fetch(url):
        source = {"url": url, "retrieved_at_utc": "2026-10-11T20:00:00+00:00", "http_status": status}
        if error:
            source["error"] = error
        return data, source
    return fetch


class ProfileTests(unittest.TestCase):
    def test_blocked_rate_limited_and_login_html_never_confirm(self):
        for status in (401, 403, 429, 503, 302, 200):
            rows, _, _ = app.username_lookup("octocat", fixture(None, status))
            self.assertFalse(any(row["status"] == "public_profile" for row in rows))

    def test_exact_provider_match_and_candidates_separate(self):
        def fetch(url):
            if "github" in url:
                return fixture({"login": "OctoCat"})(url)
            if "gitlab" in url:
                return fixture([])(url)
            return fixture({"username": "somebody_else"})(url)
        rows, sources, _ = app.username_lookup("octocat", fetch)
        self.assertEqual(len(sources), 3)
        self.assertEqual(rows[0]["status"], "public_profile")
        self.assertEqual(rows[1]["status"], "not_found_public")
        self.assertTrue(all(row["status"] == "unverified" for row in rows[2:]))

    def test_404_public_absence_not_other_provider_identity(self):
        rows, _, _ = app.username_lookup("octocat", fixture(None, 404))
        self.assertEqual([row["status"] for row in rows[:3]], ["not_found_public"] * 3)
        self.assertTrue(all(row["status"] == "unverified" for row in rows[3:]))

    def test_invalid_username_never_sent(self):
        for query in ("https://example.com", "x; touch /tmp/a", "@octocat", "", "x" * 81):
            with self.assertRaises(ValueError):
                app.username_lookup(query, lambda _: self.fail("network called"))


class CertificateTests(unittest.TestCase):
    def test_historical_wildcards_idn_and_domain_boundary(self):
        payload = [{"id": 1, "name_value": "*.example.com\napi.example.com\nbadexample.com\nexample.com.evil.test"},
                   {"id": 2, "name_value": "API.EXAMPLE.COM\nfoo..example.com\n*.sub.example.com"}]
        rows, _, limits = app.subdomain_lookup("EXAMPLE.COM.", fixture(payload))
        self.assertEqual([row["hostname"] for row in rows], ["api.example.com", "example.com", "sub.example.com"])
        self.assertEqual(rows[0]["certificate_ids"], [1, 2])
        self.assertTrue(rows[1]["wildcard_observed"])
        self.assertIn("historical", limits[0])
        self.assertEqual(app.normalize_domain("bücher.example"), "xn--bcher-kva.example")

    def test_unavailable_and_malformed_not_empty_success(self):
        rows, sources, _ = app.subdomain_lookup("example.com", fixture(None, 429, "HTTP 429"))
        self.assertFalse(rows)
        self.assertEqual(sources[0]["error"], "HTTP 429")
        rows, sources, _ = app.subdomain_lookup("example.com", fixture([None]))
        self.assertFalse(rows)
        self.assertIn("malformed", sources[0]["error"])

    def test_invalid_domain_never_sent(self):
        for query in ("https://example.com", "example.com/path", "*.example.com", "1.1.1.1", "example.com:443", "localhost"):
            with self.assertRaises(ValueError):
                app.subdomain_lookup(query, lambda _: self.fail("network called"))

    def test_certspotter_failover_and_pagination(self):
        calls = []
        def fetch(url):
            calls.append(url)
            if "crt.sh" in url:
                return fixture(None, 502, "HTTP 502")(url)
            if "after=" in url:
                return fixture([])(url)
            return fixture([{"id": "123", "dns_names": ["api.example.com", "badexample.com"]}])(url)
        rows, sources, limits = app.subdomain_lookup("example.com", fetch)
        self.assertEqual([row["hostname"] for row in rows], ["api.example.com"])
        self.assertEqual(len(calls), 3)
        self.assertEqual(sources[-1]["pagination"], "complete")
        self.assertIn("unexpired", limits[-1])
        self.assertIn("certspotter.com", rows[0]["source_urls"][0])

    def test_certspotter_pagination_cap_is_explicit(self):
        def fetch(url):
            if "crt.sh" in url:
                return fixture(None, 503, "HTTP 503")(url)
            after = int(url.rsplit("after=", 1)[-1]) if "after=" in url else 0
            return fixture([{"id": str(after + 1), "dns_names": ["api.example.com"]}])(url)
        _, sources, _ = app.subdomain_lookup("example.com", fetch)
        self.assertEqual(len(sources), 4)
        self.assertIn("three-page limit", sources[-1]["error"])


class IPTests(unittest.TestCase):
    def test_nonpublic_and_multicast_never_leave_machine(self):
        for query in ("10.0.0.1", "127.0.0.1", "::1", "fe80::1", "224.0.0.1", "192.0.2.1"):
            rows, _, _ = app.ip_lookup(query, lambda _: self.fail("external call"), lambda _: self.fail("DNS call"))
            self.assertEqual(rows[0]["public_metadata_status"], "skipped_nonpublic")

    def test_ipv6_and_exact_response_identity(self):
        query = "2606:4700:4700::1111"
        rows, _, _ = app.ip_lookup(query, fixture({"ip": query, "success": True, "connection": {"asn": 13335}}), lambda _: {"status": "unavailable"})
        self.assertEqual(rows[0]["connection"]["asn"], 13335)
        rows, sources, _ = app.ip_lookup("8.8.8.8", fixture({"ip": "1.1.1.1", "success": True}), lambda _: {})
        self.assertEqual(rows[0]["public_metadata_status"], "unavailable")
        self.assertIn("error", sources[-1])

    def test_ipv6_zone_rejected(self):
        with self.assertRaises(ValueError):
            app.ip_lookup("fe80::1%wlan0")


class PhoneTests(unittest.TestCase):
    def test_offline_format_and_region(self):
        rows, sources, limits = app.phone_lookup("202-555-0123", "US")
        self.assertEqual(rows[0]["e164"], "+12025550123")
        self.assertTrue(rows[0]["possible_format"])
        self.assertEqual(sources[0]["method"], "offline numbering-plan metadata")
        self.assertTrue(any("active" in limit for limit in limits))

    def test_international_and_invalid_input(self):
        rows, _, _ = app.phone_lookup("+442083661177", "US")
        self.assertEqual(rows[0]["region_code"], "GB")
        for query, region in (("not a number", "US"), ("123", "XX")):
            with self.assertRaises(ValueError):
                app.phone_lookup(query, region)


class TransportAndEvidenceTests(unittest.TestCase):
    def test_fetch_handles_http_errors_and_invalid_json(self):
        for code in (403, 429):
            error = urllib.error.HTTPError("https://example.com", code, "blocked", {"Retry-After": "60"}, None)
            with patch("urllib.request.OpenerDirector.open", side_effect=error):
                data, source = app.fetch_json("https://example.com")
            self.assertIsNone(data)
            self.assertEqual(source["http_status"], code)
            self.assertEqual(source["retry_after"], "60")
        class Response(io.BytesIO):
            status = 200
        with patch("urllib.request.OpenerDirector.open", return_value=Response(b"<html>login</html>")):
            data, source = app.fetch_json("https://example.com")
        self.assertIsNone(data)
        self.assertIn("error", source)

    def test_fetch_size_cap_and_hash(self):
        class Response(io.BytesIO):
            status = 200
        with patch("urllib.request.OpenerDirector.open", return_value=Response(b"[1]")):
            data, source = app.fetch_json("https://example.com")
        self.assertEqual(data, [1])
        self.assertEqual(len(source["response_sha256"]), 64)
        with patch.object(app, "MAX_BYTES", 8), patch("urllib.request.OpenerDirector.open", return_value=Response(b"x" * 20)):
            data, source = app.fetch_json("https://example.com")
        self.assertIsNone(data)
        self.assertIn("limit", source["error"])

    def test_evidence_unique_private_and_errors_preserved(self):
        with tempfile.TemporaryDirectory(prefix="osint-case '") as tmp:
            case = Path(tmp)
            with contextlib.redirect_stdout(io.StringIO()):
                for _ in range(2):
                    self.assertEqual(app.main(["phone", "+12025550123", "--case-dir", tmp]), 0)
                self.assertEqual(app.main(["subdomains", "bad;command", "--case-dir", tmp]), 1)
            files = sorted((case / "osint").glob("*.json"))
            self.assertEqual(len(files), 3)
            reports = [json.loads(path.read_text()) for path in files]
            self.assertEqual(sum(report["status"] == "error" for report in reports), 1)
            self.assertEqual(len(list((case / "osint").glob("*.md"))), 3)
            for file in (case / "osint").iterdir():
                self.assertEqual(os.stat(file).st_mode & 0o777, 0o600)
            self.assertTrue(all(report["tool_sha256"] for report in reports))

    def test_missing_case_not_created_and_terminal_escapes_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing"
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(app.main(["phone", "+12025550123", "--case-dir", str(missing)]), 1)
            self.assertFalse(missing.exists())
        self.assertNotIn("\x1b", app.clean_text("name\x1b[31m"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
