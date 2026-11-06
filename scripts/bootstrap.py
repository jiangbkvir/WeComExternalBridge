from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
from datetime import datetime
from pathlib import Path

import frida

ROOT = Path(__file__).resolve().parents[1]
SUPPORT_DIR = Path.home() / "Library" / "Application Support" / "com.local.wecom-frida"
TOKEN_PATH = SUPPORT_DIR / "token"
LOCAL_CONFIG_PATH = ROOT / "config.json"
PLATFORM_ID = "wecom_external_bridge"


def compile_agent(name: str) -> None:
    source = ROOT / "agent" / f"{name}.ts"
    target = ROOT / "agent" / f"{name}.js"
    compiler = frida.Compiler()
    diagnostics: list[str] = []
    compiler.on("diagnostics", lambda value: diagnostics.append(str(value)))
    output = compiler.build(str(source), project_root=str(ROOT))
    if diagnostics:
        raise RuntimeError("; ".join(diagnostics))
    target.write_text(output, encoding="utf-8")


def write_private_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(path, 0o600)


def read_or_create_frida_token() -> str:
    if TOKEN_PATH.is_file():
        token = TOKEN_PATH.read_text(encoding="utf-8").strip()
        if token:
            os.chmod(TOKEN_PATH, 0o600)
            return token
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(36)
    TOKEN_PATH.write_text(token + "\n", encoding="utf-8")
    os.chmod(TOKEN_PATH, 0o600)
    return token


def load_config() -> dict:
    example = json.loads(
        (ROOT / "config.example.json").read_text(encoding="utf-8")
    )
    if LOCAL_CONFIG_PATH.is_file():
        existing = json.loads(
            LOCAL_CONFIG_PATH.read_text(encoding="utf-8")
        )
        for key in example:
            if key in existing:
                example[key] = existing[key]

    example["frida_token"] = read_or_create_frida_token()
    write_private_json(LOCAL_CONFIG_PATH, example)
    return example


def update_astrbot_platform(
    config_path: Path,
    bridge_config: dict,
    enable_platform: bool,
) -> None:
    if not config_path.is_file():
        raise FileNotFoundError(f"AstrBot config not found: {config_path}")
    value = json.loads(config_path.read_text(encoding="utf-8-sig"))
    platform_list = value.setdefault("platform", [])
    if not isinstance(platform_list, list):
        raise ValueError("AstrBot platform config is not an array")

    platform = next(
        (
            item
            for item in platform_list
            if isinstance(item, dict) and item.get("id") == PLATFORM_ID
        ),
        None,
    )
    if platform is None:
        platform = {"id": PLATFORM_ID, "type": PLATFORM_ID}
        platform_list.append(platform)

    platform.update(
        {
            "type": PLATFORM_ID,
            "enable": bool(enable_platform),
            "frida_host": str(
                bridge_config.get("frida_host")
                or "host.docker.internal"
            ),
            "frida_port": int(bridge_config.get("frida_port") or 27042),
            "frida_token": str(bridge_config["frida_token"]),
            "frida_connect_timeout_seconds": int(
                bridge_config.get("frida_connect_timeout_seconds") or 15
            ),
            "process_name": str(
                bridge_config.get("process_name") or "企业微信"
            ),
            "wecom_pid": int(bridge_config.get("wecom_pid") or 0),
            "allowed_group_ids": list(
                bridge_config.get("allowed_group_ids", [])
            ),
            "bot_user_id": str(bridge_config.get("bot_user_id") or ""),
            "bot_display_name": str(
                bridge_config.get("bot_display_name") or "数字员工"
            ),
            "capture_only": bool(bridge_config.get("capture_only", True)),
            "send_enabled": bool(bridge_config.get("send_enabled", False)),
            "require_outer_group": bool(
                bridge_config.get("require_outer_group", True)
            ),
            "require_mention_id_match": bool(
                bridge_config.get("require_mention_id_match", True)
            ),
            "max_text_chars": int(
                bridge_config.get("max_text_chars") or 4000
            ),
            "poll_interval_seconds": float(
                bridge_config.get("poll_interval_seconds") or 0.75
            ),
            "poll_message_count": int(
                bridge_config.get("poll_message_count") or 50
            ),
            "reconnect_seconds": float(
                bridge_config.get("reconnect_seconds") or 3
            ),
            "reply_aggregate_seconds": float(
                bridge_config.get("reply_aggregate_seconds") or 0.5
            ),
            "send_min_interval_seconds": float(
                bridge_config.get("send_min_interval_seconds") or 0.2
            ),
            "sent_echo_guard_seconds": int(
                bridge_config.get("sent_echo_guard_seconds") or 86400
            ),
            "event_retention_days": int(
                bridge_config.get("event_retention_days") or 7
            ),
        }
    )

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = config_path.with_name(
        f"{config_path.name}.bak-wecom-bridge-{stamp}"
    )
    shutil.copy2(config_path, backup)
    os.chmod(backup, 0o600)
    config_path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8-sig",
    )
    os.chmod(config_path, 0o600)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="编译 Frida Agent 并写入 AstrBot 平台配置"
    )
    parser.add_argument(
        "--astrbot-config",
        type=Path,
        help="AstrBot 的 cmd_config.json；不填则只生成本地配置",
    )
    parser.add_argument("--enable-platform", action="store_true")
    parser.add_argument(
        "--enable-send",
        action="store_true",
        help="Disable capture-only mode and enable native text sending.",
    )
    parser.add_argument("--group-id", action="append", default=[])
    parser.add_argument("--bot-user-id")
    parser.add_argument("--bot-display-name")
    parser.add_argument("--skip-compile", action="store_true")
    args = parser.parse_args()

    if not args.skip_compile:
        compile_agent("monitor")
        compile_agent("probe")

    config = load_config()
    if args.group_id:
        config["allowed_group_ids"] = args.group_id
    if args.bot_user_id is not None:
        config["bot_user_id"] = args.bot_user_id
    if args.bot_display_name is not None:
        config["bot_display_name"] = args.bot_display_name
    if args.enable_send:
        config["capture_only"] = False
        config["send_enabled"] = True
    write_private_json(LOCAL_CONFIG_PATH, config)

    if args.astrbot_config is not None:
        update_astrbot_platform(
            args.astrbot_config,
            config,
            enable_platform=args.enable_platform,
        )
        state = "enabled" if args.enable_platform else "disabled"
        print(f"AstrBot platform written: {args.astrbot_config} ({state})")
    else:
        print("AstrBot platform not written; use --astrbot-config to update it")

    print(f"Local config: {LOCAL_CONFIG_PATH}")
    print(f"Frida token: {TOKEN_PATH}")
    print("bootstrap complete")


if __name__ == "__main__":
    main()
