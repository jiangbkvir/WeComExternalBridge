# 适配与可行性记录

## 已验证环境

- macOS 企业微信 `5.0.8`。
- Python Frida `17.26.0`。
- 仅附加企业微信 `com.tencent.WeWorkMac`，未附加个人微信。
- AstrBot `4.29.3`。

企业微信内部类和方法不是公开 API。以下结论只代表上述测试环境，不能保证
后续客户端版本继续兼容。

## 消息读取

- `WEWMessageService.fetchConversationMessages:messageId:count:callback:`
  可读取指定会话的最近消息。
- `WEWConversationService.conversationWithId:` 可验证群会话及其外部群属性。
- `WEWMessage` 可读取稳定消息 ID、发送者 ID、消息方向和文本内容。
- 文本消息的 protobuf 内容可提取正文、@ 目标 ID 和消息项类型。
- 实时 hook 未作为生产路径；当前使用原生消息服务轮询，降低对客户端主线程的
  侵入。
- 回调 block 需要按群长期复用。频繁创建并释放 block 可能导致企业微信崩溃。

## 事件过滤

进入 AstrBot 前同时执行以下校验：

- 群 ID 在本地白名单内。
- 会话必须是外部客户群。
- 消息类型必须是文本。
- 必须明确 `@` 到配置的数字员工 user ID。
- 发送者不能是数字员工自身。
- 空文本、超长文本和近期已发送文本回声必须拒绝。
- 同一群内同一消息 ID 只形成一次事件。

## 原生发送

- 已通过 `WEWMessageService` 的
  `sendMultiMediaMessage:isAnonymity:toConversation:resultCallback:` 路径，
  配合 `WEWMultiMediaObject.addText:isNeedConfirm:` 完成纯文本发送验证。
- 发送验证不依赖 UI、鼠标键盘、剪贴板或窗口焦点。
- 发送请求由 AstrBot 插件持久化，使用 `request_id` 防止重复发送。
- `send_enabled=false` 时不会调用任何原生发送方法。

## 已排除

- `WEWForwardMessageHelper.forwardTextAsMessage:formConv:` 会触发窗口相关异常，
  不作为发送路径。
- 额外建立第二个 Frida 会话运行 tracer 可能破坏企业微信稳定性，不采用。
- 不使用截屏、OCR、鼠标键盘模拟或 UI 自动化作为回退。
- 不附加、读取或操作个人微信。

## 上线门槛

1. 只读模式能稳定收到目标群事件。
2. 非白名单、非外部群、非文本、非 @、自身消息均被过滤。
3. 受控测试确认回复进入正确群，且桌面焦点不变化。
4. 重启企业微信、AstrBot 和 Frida 服务后不重复回复。
5. 客户端升级后重新执行只读验证，再决定是否恢复发送。

## 风险

- 内部方法随企业微信版本变化可能失效。
- 非官方接入存在账号风控、稳定性和合规风险。
- 只应在获得授权的数字员工账号和外部客户群中使用。
