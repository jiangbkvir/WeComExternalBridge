#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import http.client
import lzma
import os
import platform
import plistlib
import secrets
import shlex
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

FRIDA_VERSION = "17.26.0"
LABEL = "com.local.wecom-frida-server"
DEFAULT_PORT = 27042


@dataclass(frozen=True)
class Asset:
    name: str
    sha256: str


ASSETS = {
    "arm64": Asset(
        "frida-server-17.26.0-macos-arm64.xz",
        "f1280cfc211421ca27df8820b7194ba1caf1d59025757e78dadcbd2d96d601e1",
    ),
    "x86_64": Asset(
        "frida-server-17.26.0-macos-x86_64.xz",
        "6c1581a92361a3e7dc08ac5c32e72fe062e7b0301598506d06ed5e81cc521f63",
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install a token-protected frida-server LaunchAgent."
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--support-dir",
        type=Path,
        default=(
            Path.home()
            / "Library"
            / "Application Support"
            / "com.local.wecom-frida"
        ),
    )
    parser.add_argument(
        "--launch-agent-dir",
        type=Path,
        default=Path.home() / "Library" / "LaunchAgents",
    )
    parser.add_argument(
        "--no-load",
        action="store_true",
        help="Install files without loading the LaunchAgent.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the selected asset and target paths only.",
    )
    parser.add_argument(
        "--archive",
        type=Path,
        help="Use an already downloaded frida-server .xz archive.",
    )
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, target: Path, attempts: int = 4) -> None:
    last_error: BaseException | None = None
    for attempt in range(1, attempts + 1):
        existing_size = target.stat().st_size if target.exists() else 0
        headers = {
            "User-Agent": f"WeComExternalBridge/{FRIDA_VERSION}",
        }
        if existing_size:
            headers["Range"] = f"bytes={existing_size}-"
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                append = existing_size > 0 and response.status == 206
                mode = "ab" if append else "wb"
                with target.open(mode) as file:
                    while chunk := response.read(1024 * 1024):
                        file.write(chunk)
            return
        except (
            OSError,
            TimeoutError,
            http.client.HTTPException,
            urllib.error.URLError,
        ) as error:
            last_error = error
            if attempt < attempts:
                print(
                    f"download interrupted (attempt {attempt}/{attempts}); "
                    "retrying with resume...",
                    flush=True,
                )
                time.sleep(attempt * 2)
    raise RuntimeError(
        "download failed after retries; use --archive with a local "
        f"frida-server archive: {last_error}"
    )


def read_or_create_token(path: Path) -> str:
    if path.is_file():
        token = path.read_text(encoding="utf-8").strip()
        if token:
            os.chmod(path, 0o600)
            return token
    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(36)
    path.write_text(token + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return token


def build_wrapper(server_path: Path, token_path: Path, port: int) -> str:
    server = shlex.quote(str(server_path))
    token_file = shlex.quote(str(token_path))
    return "\n".join(
        [
            "#!/bin/zsh",
            "set -eu",
            "umask 077",
            f'token="$(< {token_file})"',
            (
                f"exec {server} -l {shlex.quote(f'0.0.0.0:{port}')} "
                '--token "$token"'
            ),
            "",
        ]
    )


def install_launch_agent(
    launch_agent_dir: Path,
    wrapper_path: Path,
    log_path: Path,
    error_log_path: Path,
) -> Path:
    launch_agent_dir.mkdir(parents=True, exist_ok=True)
    plist_path = launch_agent_dir / f"{LABEL}.plist"
    plist = {
        "Label": LABEL,
        "ProgramArguments": [str(wrapper_path)],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 5,
        "StandardOutPath": str(log_path),
        "StandardErrorPath": str(error_log_path),
    }
    plist_path.write_bytes(plistlib.dumps(plist, sort_keys=False))
    os.chmod(plist_path, 0o600)
    return plist_path


def load_launch_agent(plist_path: Path, port: int) -> None:
    domain = f"gui/{os.getuid()}"
    service = f"{domain}/{LABEL}"
    subprocess.run(
        ["launchctl", "bootout", service],
        check=False,
        capture_output=True,
    )
    subprocess.run(
        ["launchctl", "bootstrap", domain, str(plist_path)],
        check=True,
    )
    subprocess.run(
        ["launchctl", "kickstart", "-k", service],
        check=True,
    )
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.25)
    raise RuntimeError("frida-server did not start; check the LaunchAgent logs")


def main() -> None:
    args = parse_args()
    machine = platform.machine()
    asset = ASSETS.get(machine)
    if asset is None:
        supported = ", ".join(sorted(ASSETS))
        raise SystemExit(
            f"Unsupported architecture {machine!r}; expected {supported}"
        )

    support_dir = args.support_dir.expanduser().resolve()
    server_path = support_dir / "frida-server"
    token_path = support_dir / "token"
    wrapper_path = support_dir / "run_frida_server.zsh"
    logs_dir = Path.home() / "Library" / "Logs"
    log_path = logs_dir / f"{LABEL}.log"
    error_log_path = logs_dir / f"{LABEL}.error.log"
    url = (
        f"https://github.com/frida/frida/releases/download/"
        f"{FRIDA_VERSION}/{asset.name}"
    )

    print(f"frida-server: {FRIDA_VERSION}")
    print(f"architecture: {machine}")
    print(f"asset: {asset.name}")
    print(f"support directory: {support_dir}")
    if args.dry_run:
        print(f"download: {url}")
        print(f"sha256: {asset.sha256}")
        return

    support_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(support_dir, 0o700)
    logs_dir.mkdir(parents=True, exist_ok=True)
    for path in (log_path, error_log_path):
        path.touch(mode=0o600, exist_ok=True)
        os.chmod(path, 0o600)

    with tempfile.TemporaryDirectory(dir=support_dir) as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        archive_path = temp_dir / asset.name
        if args.archive is not None:
            source_archive = args.archive.expanduser().resolve()
            if not source_archive.is_file():
                raise FileNotFoundError(source_archive)
            print(f"using archive: {source_archive}")
            archive_path = source_archive
        else:
            print("downloading...", flush=True)
            download(url, archive_path)
        actual_sha256 = sha256_file(archive_path)
        if actual_sha256 != asset.sha256:
            raise RuntimeError(
                "SHA256 mismatch: "
                f"expected {asset.sha256}, received {actual_sha256}"
            )

        extracted_path = temp_dir / "frida-server"
        print("extracting...", flush=True)
        with lzma.open(archive_path, "rb") as source:
            with extracted_path.open("wb") as target:
                while chunk := source.read(1024 * 1024):
                    target.write(chunk)
        with extracted_path.open("rb") as file:
            if file.read(4) != b"\xcf\xfa\xed\xfe":
                raise RuntimeError("Downloaded file is not a Mach-O executable")
        os.chmod(extracted_path, 0o700)
        os.replace(extracted_path, server_path)

    read_or_create_token(token_path)
    wrapper_path.write_text(
        build_wrapper(server_path, token_path, args.port),
        encoding="utf-8",
    )
    os.chmod(wrapper_path, 0o700)
    plist_path = install_launch_agent(
        args.launch_agent_dir.expanduser().resolve(),
        wrapper_path,
        log_path,
        error_log_path,
    )

    if not args.no_load:
        print("loading LaunchAgent...")
        load_launch_agent(plist_path, args.port)

    print(f"installed: {server_path}")
    print(f"token file: {token_path}")
    print(f"LaunchAgent: {plist_path}")
    print("Copy the token file contents into AstrBot's frida_token setting.")


if __name__ == "__main__":
    main()
