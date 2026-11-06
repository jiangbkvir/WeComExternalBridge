# WeComExternalBridge

macOS 企业微信外部客户群数字员工接入工具，配合 AstrBot 平台适配器
[`astrbot_plugin_wecom_external_bridge`](https://github.com/jiangbkvir/astrbot_plugin_wecom_external_bridge)
使用。

本项目只附加企业微信 `com.tencent.WeWorkMac` 进程，读取明确 `@数字员工`
的外部客户群文本消息，并通过企业微信原生文本发送接口回复。不使用个人微信，
不截屏，不模拟鼠标键盘，也不抢占企业微信前台。

> 这是非官方实现。企业微信升级可能导致内部接口失效，并存在账号风控风险。
> 请使用公司授权账号，并遵守企业微信服务条款和所在地法律法规。

## 运行架构

```text
外部客户群 @数字员工
  -> macOS 企业微信进程
  -> 官方 frida-server（Docker/远程传输层）
  -> AstrBot 插件内的 Frida Agent
       -> 群白名单 / 外部群校验
       -> 文本、@ 目标、发送者方向校验
       -> SQLite 事件与发送去重
       -> AstrBot 默认 LLM / 人格 / 插件
       -> 企业微信原生文本发送接口
  -> 回写同一外部客户群
```

不再运行独立 HTTP 桥接服务。消息过滤、状态持久化和发送流程都在 AstrBot
插件进程内完成。

## 本仓库内容

```text
agent/
  monitor.ts         消息轮询、解析和原生发送 Agent 源码
  monitor.js         编译后的 Agent，插件实际加载
  probe.ts           只读探针源码
  probe.js           编译后的只读探针
scripts/
  install_frida_server.py  下载、校验并安装 frida-server LaunchAgent
  bootstrap.py             编译 Agent、生成配置、写入 AstrBot 配置
config.example.json  配置模板
docs/FEASIBILITY.md  适配范围和风险说明
```

## 前提

- macOS 13 或更高版本，支持 Apple Silicon 和 Intel。
- 已登录企业微信，且数字员工账号可加入目标外部客户群。
- AstrBot `>=4.29,<5`，插件 `astrbot_plugin_wecom_external_bridge`。
- Python 3.10+、Node.js 18+ 和 npm。
- AstrBot 能通过 `host.docker.internal:27042` 或自定义地址访问宿主机。

## 安装依赖

```bash
cd WeComExternalBridge
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
npm install
```

## 安装 Frida 服务

安装器只下载 Frida 官方 `17.26.0` 发布包，先校验 SHA256，再安装到当前用户目录：

```bash
.venv/bin/python scripts/install_frida_server.py
```

默认行为：

- 安装 `frida-server` 到 `~/Library/Application Support/com.local.wecom-frida/`。
- 将随机 Token 写入同目录的 `token`，权限为 `0600`。
- 创建并加载 `~/Library/LaunchAgents/com.local.wecom-frida-server.plist`。
- 监听 `0.0.0.0:27042`，服务端必须有 Token 才能连接。

安装器不会打印 Token。之后将 `token` 文件内容填入 AstrBot 的
`frida_token` 配置。重复运行安装器会保留现有 Token。

如果不需要立即启动服务：

```bash
.venv/bin/python scripts/install_frida_server.py --no-load
```

如果 GitHub 下载不稳定，可先从 Frida 官方 Release 手动下载对应架构的
`frida-server-17.26.0-macos-*.xz`，再通过本地文件安装：

```bash
.venv/bin/python scripts/install_frida_server.py \
  --archive /path/to/frida-server-17.26.0-macos-arm64.xz
```

## 编译 Agent 并写入配置

先用真实的企业微信群 ID 和数字员工 user ID 替换下面的占位符。不要把真实值
提交到 Git 仓库或 Issue。

只读验证阶段：

```bash
.venv/bin/python scripts/bootstrap.py \
  --astrbot-config '/path/to/AstrBot/data/cmd_config.json' \
  --group-id 'R:REPLACE_GROUP_ID' \
  --bot-user-id 'REPLACE_BOT_USER_ID' \
  --bot-display-name '数字员工'
```

参数说明：

- `--group-id` 可重复，用于添加多个白名单外部群。
- 不传 `--enable-platform` 时，平台会写入但保持禁用。
- 不传 `--enable-send` 时，默认保持 `capture_only=true` 和 `send_enabled=false`。
- 脚本会备份 AstrBot 配置，权限统一设置为 `0600`。

## 启用与验收

1. 在 AstrBot 中确认 `wecom_external_bridge` 平台已启用。
2. 保持只读模式，在目标外部群发送 `@数字员工 测试`。
3. 在 AstrBot 日志确认事件进入，且不会触发发送。
4. 验证不 `@` 的文本、图片、语音和机器人自身消息均被过滤。
5. 确认群、账号和回复目标无误后，再开启原生发送：

```bash
.venv/bin/python scripts/bootstrap.py \
  --astrbot-config '/path/to/AstrBot/data/cmd_config.json' \
  --group-id 'R:REPLACE_GROUP_ID' \
  --bot-user-id 'REPLACE_BOT_USER_ID' \
  --bot-display-name '数字员工' \
  --enable-platform \
  --enable-send
```

`--enable-send` 会关闭只读模式并允许向白名单群发送纯文本。启用前请先完成
只读和原生发送的受控验证。

## 安全边界

- 只处理白名单外部群。
- 只处理明确 `@数字员工` 的文本消息。
- 不回复机器人自身消息或已发送文本回声。
- 不读取、附加或操作个人微信。
- 图片、语音、文件、私聊和主动群发不在当前支持范围。
- 日志不打印 Token 和聊天正文。
- 真实配置、SQLite、日志和 Token 均被 `.gitignore` 排除。

## 故障排查

查看服务状态和日志：

```bash
launchctl print "gui/$(id -u)/com.local.wecom-frida-server"
tail -n 100 "$HOME/Library/Logs/com.local.wecom-frida-server.error.log"
```

检查端口：

```bash
lsof -nP -iTCP:27042 -sTCP:LISTEN
```

企业微信升级后，如果 AstrBot 持续报告 Frida Agent 健康检查失败或找不到
内部类，应停止发送并重新验证适配层，不要用 UI 自动化回退。

## License

[MIT](LICENSE)
