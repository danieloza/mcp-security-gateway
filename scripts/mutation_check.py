"""Remove one security guard at a time and check that a test fails.

Each mutation edits one guard in the source, runs the matching test file, and
restores the file byte for byte, also when the run is interrupted. A mutation
that leaves the tests green is a guard that no test protects.

Run from the repository root, in the project's environment:

    python scripts/mutation_check.py            # both suites
    python scripts/mutation_check.py proxy      # or: oauth
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import ci_summary  # scripts/ci_summary.py

MAIN = "src/mcp_security_gateway/main.py"
OAUTH = "src/mcp_security_gateway/oauth.py"
SERVICES = "src/mcp_security_gateway/services.py"
UPSTREAM = "src/mcp_security_gateway/upstream.py"

# Each mutation: (guard, file, [(anchor, replacement), ...]). Every anchor must
# occur exactly once in its file, so a refactor that moves a guard is reported
# instead of silently testing nothing.
SUITES: dict[str, tuple[str, list[tuple[str, str, list[tuple[str, str]]]]]] = {
    "proxy": (
        "tests/test_upstream.py",
        [
            ("call-time re-check dropped", SERVICES, [
                ('if self.upstreams.get(server.id) and manifest.trust_status == "verified":', "if False:"),
            ]),
            ("pre-forward re-check dropped", SERVICES, [
                ("            drift = self._upstream_drift(manifest)\n"
                 "        except UpstreamError as exc:\n"
                 '            raise PermissionError(f"Upstream could not be re-verified',
                 "            drift = None\n"
                 "        except UpstreamError as exc:\n"
                 '            raise PermissionError(f"Upstream could not be re-verified'),
            ]),
            ("output inspection dropped", SERVICES, [
                ("findings = inspect_value(output)", "findings = []"),
            ]),
            ("poisoning scan at sync dropped", SERVICES, [
                ("if poisoned:", "if False:"),
            ]),
            ("quarantined tools listed to the agent", SERVICES, [
                ('for item in self.list_tools(auth) if item.trust_status == "verified"]',
                 "for item in self.list_tools(auth)]"),
            ]),
            ("caller's credential passed upstream", UPSTREAM, [
                ('if session:\n            headers["Mcp-Session-Id"] = session',
                 'headers["Authorization"] = "Bearer msg-ops-demo"\n'
                 '        if session:\n            headers["Mcp-Session-Id"] = session'),
            ]),
            ("redirects followed", UPSTREAM, [
                ("if response.is_redirect:", "if False:"),
            ]),
            ("response size not capped", UPSTREAM, [
                ("if len(body) > MAX_RESPONSE_BYTES:", "if False:"),
            ]),
            ("sync allowed for any role", SERVICES, [
                ('raise PermissionError("Only security or platform admins can sync an upstream server.")', "pass"),
            ]),
            ("withheld output shown to operators as a plain execution", SERVICES, [
                ('("output_withheld" if withheld else "executed") if succeeded', '"executed" if succeeded'),
            ]),
            ("withheld output may be executed again", SERVICES, [
                ('{"executed", "output_withheld", "failed"}', '{"executed", "failed"}'),
            ]),
        ],
    ),
    "oauth": (
        "tests/test_oauth.py",
        [
            ("audience check dropped", OAUTH, [
                ('options={"require": ["exp", "iss", "aud", "sub"]},',
                 'options={"require": ["exp", "iss", "sub"], "verify_aud": False},'),
            ]),
            ("issuer check dropped", OAUTH, [
                ("issuer=self.settings.issuer,", "issuer=None,"),
            ]),
            # Trusting the header's algorithm alone is an equivalent mutant while
            # the allowlist check before key lookup stands, so both go together.
            ("both algorithm checks removed (header alg trusted)", OAUTH, [
                ('if header.get("alg") not in self.settings.algorithms:', "if False:"),
                ("algorithms=list(self.settings.algorithms),", 'algorithms=[header.get("alg")],'),
            ]),
            ("algorithm allowlist skipped before key lookup", OAUTH, [
                ('if header.get("alg") not in self.settings.algorithms:', "if False:"),
            ]),
            ("symmetric algorithms allowed in settings", OAUTH, [
                ("if unsafe or not algorithms:", "if not algorithms:"),
            ]),
            ("scope check dropped", MAIN, [
                ("if scope not in verified.scopes:", "if False:"),
            ]),
            ("unknown subject mapped to the operator", MAIN, [
                ("user_id = oauth.settings.subjects.get(verified.subject)",
                 'user_id = oauth.settings.subjects.get(verified.subject, "usr_ops")'),
            ]),
            ("X-API-Key tolerated next to a token", MAIN, [
                ("if not authorization or x_api_key is not None:", "if not authorization:"),
            ]),
            ("expiry not required", OAUTH, [
                ('"require": ["exp", "iss", "aud", "sub"]',
                 '"require": ["iss", "aud", "sub"], "verify_exp": False'),
            ]),
        ],
    ),
}


def run_suite(name: str, rows: list[tuple[str, str, str]]) -> int:
    tests, mutations = SUITES[name]
    survived = 0
    print(f"[{name}] {len(mutations)} mutations against {tests}")
    for guard, path, edits in mutations:
        file = pathlib.Path(path)
        original = file.read_bytes()
        text = original.decode("utf-8")
        eol = "\r\n" if "\r\n" in text else "\n"
        pairs = [(anchor.replace("\n", eol), new.replace("\n", eol)) for anchor, new in edits]
        if any(text.count(anchor) != 1 for anchor, _ in pairs):
            print(f"  SETUP ERROR  {guard}: an anchor is missing or repeated in {path}")
            rows.append((name, guard, "setup error"))
            survived += 1
            continue
        for anchor, new in pairs:
            text = text.replace(anchor, new)
        try:
            file.write_bytes(text.encode("utf-8"))
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", tests],
                capture_output=True,
                text=True,
            )
        finally:
            file.write_bytes(original)
        if file.read_bytes() != original:
            raise SystemExit(f"Could not restore {path}; check it before doing anything else.")
        last = (result.stdout.strip().splitlines() or ["?"])[-1]
        if result.returncode == 0:
            survived += 1
            rows.append((name, guard, "**survived**"))
            print(f"  SURVIVED     {guard}: {last}")
        else:
            rows.append((name, guard, "caught"))
            print(f"  CAUGHT       {guard}: {last}")
    return survived


def write_summary(rows: list[tuple[str, str, str]], survived: int) -> None:
    """Show the result on the GitHub Actions run page, when running there."""
    caught = len(rows) - survived
    verdict = f"**{caught} of {len(rows)} mutations caught.**" if survived == 0 else f"**{survived} of {len(rows)} not caught.**"
    ci_summary.append("Mutation check", "", ["Suite", "Guard removed", "Result"], rows, verdict)


def main(argv: list[str]) -> int:
    names = argv or list(SUITES)
    unknown = [name for name in names if name not in SUITES]
    if unknown:
        print(f"Unknown suite: {', '.join(unknown)}. Choose from: {', '.join(SUITES)}.")
        return 2
    rows: list[tuple[str, str, str]] = []
    survived = sum(run_suite(name, rows) for name in names)
    print("All mutations caught." if survived == 0 else f"{survived} mutation(s) not caught.")
    write_summary(rows, survived)
    return 1 if survived else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
