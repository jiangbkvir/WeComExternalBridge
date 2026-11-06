import ObjC from "frida-objc-bridge";

type Payload = Record<string, unknown>;

function readString(obj: any, selector: string): string | null {
  try {
    const value = obj[selector]();
    return value === null || value === undefined ? null : String(value);
  } catch {
    return null;
  }
}

function readBool(obj: any, selector: string): boolean | null {
  try {
    return Boolean(obj[selector]());
  } catch {
    return null;
  }
}

function readNumber(obj: any, selector: string): number | null {
  try {
    return Number(obj[selector]());
  } catch {
    return null;
  }
}

function conversationPayload(conversation: any): Payload {
  return {
    className: conversation.$className,
    id: readString(conversation, "conversationId"),
    name: readString(conversation, "name"),
    type: readNumber(conversation, "conversationType"),
    creatorId: readString(conversation, "creatorId"),
    isOuterGroup: readBool(conversation, "isOuterGroupConversation"),
    isWeChatCustomer: readBool(
      conversation,
      "isWeChatWorkCustomerConversation",
    ),
    isWXWorkTeam: readBool(conversation, "isWXWorkTeamConversation"),
    isCorp: readBool(conversation, "isCorpConversation"),
  };
}

function messagePayload(message: any, includeText: boolean): Payload {
  const result: Payload = {
    className: message.$className,
    msgKey: readString(message, "msgKey"),
    isSelf: readBool(message, "amISender"),
    isAtMe: readBool(message, "isAtMeMessage"),
    isAtAll: readBool(message, "isAtAllMessage"),
    type: readNumber(message, "type"),
    timestamp: null,
    textLength: null,
    text: null,
    sender: null,
    conversation: null,
    mentions: [],
    items: [],
  };

  try {
    const text = message.text();
    if (text !== null && text !== undefined) {
      const value = String(text);
      result.textLength = value.length;
      if (includeText) {
        result.text = value;
      }
    }
  } catch {}

  try {
    const date = message.date();
    result.timestamp =
      date === null || date === undefined
        ? null
        : Number(date.timeIntervalSince1970());
  } catch {}

  try {
    const user = message.attachUser();
    if (user !== null && user !== undefined) {
      result.sender = {
        className: user.$className,
        id: readString(user, "userId"),
        name: readString(user, "name"),
        realName: readString(user, "realName"),
      };
    }
  } catch {}

  try {
    const conversation = message.attachConv();
    if (conversation !== null && conversation !== undefined) {
      result.conversation = conversationPayload(conversation);
    }
  } catch {}

  try {
    const items = message.messageItems();
    if (items !== null && items !== undefined) {
      const count = Number(items.count());
      const itemPayload: Payload[] = [];
      for (let index = 0; index < count; index += 1) {
        const item = items.objectAtIndex_(index);
        const entry: Payload = {
          className: item.$className,
          fromVid: readString(item, "fromVid"),
          atVid: readString(item, "atVid"),
          textLength: null,
        };
        try {
          const itemText = item.text();
          if (itemText !== null && itemText !== undefined) {
            entry.textLength = String(itemText).length;
          }
        } catch {}
        itemPayload.push(entry);
        if (entry.atVid !== null) {
          (result.mentions as string[]).push(String(entry.atVid));
        }
      }
      result.items = itemPayload;
    }
  } catch {}

  return result;
}

function wewMessagePayload(message: any, includeText: boolean): Payload {
  const result: Payload = {
    className: message.$className,
    messageId: readString(message, "messageId"),
    serverId: readString(message, "serverId"),
    clientId: readString(message, "clientId"),
    conversationId: readString(message, "conversationId"),
    senderId: readString(message, "senderId"),
    senderName: readString(message, "senderName"),
    realSenderName: readString(message, "realSenderName"),
    contentType: readNumber(message, "contentType"),
    cppContentType: readNumber(message, "cppContentType"),
    sendTime: readNumber(message, "sendTime"),
    isSendFromMac: readBool(message, "isSendFromMac"),
    isNormalMessage: readBool(message, "isNormalMessage"),
    isGeneralTextMsg: readBool(message, "isGeneralTextMsg"),
    isVoiceMessage: readBool(message, "isVoiceMessage"),
    contentLength: null,
    content: null,
    contentHex: null,
    rawContentClass: null,
  };

  try {
    const content = message.content();
    if (content !== null && content !== undefined) {
      const value = String(content);
      result.contentLength = value.length;
      if (includeText) {
        result.content = value;
        try {
          const length = Number(content.length());
          const bytes = content.bytes().readByteArray(Math.min(length, 4096));
          result.contentHex = Array.from(new Uint8Array(bytes))
            .map((byte) => byte.toString(16).padStart(2, "0"))
            .join("");
        } catch {}
      }
    }
  } catch {}

  try {
    const rawContent = message.rawContent();
    result.rawContentClass =
      rawContent === null || rawContent === undefined
        ? null
        : String(rawContent.$className ?? typeof rawContent);
  } catch {}

  return result;
}

rpc.exports = {
  inspect(patternSource: string): Record<string, unknown> {
    const classesByModule = ObjC.enumerateLoadedClassesSync();
    const classes = Object.values(classesByModule).flat();
    const pattern = new RegExp(patternSource);

    const picked = classes
      .filter((name: string) => pattern.test(name))
      .slice(0, 200)
      .map((name: string) => {
        try {
          const cls = ObjC.classes[name];
          return {
            name,
            superclass: cls.$superClass?.$className ?? null,
            methods: cls.$ownMethods.slice(0, 240),
          };
        } catch (error) {
          return { name, error: String(error) };
        }
      });

    return {
      ok: true,
      totalClasses: classes.length,
      picked,
    };
  },

  describeClass(name: string): Record<string, unknown> {
    const cls = ObjC.classes[name];
    if (cls === undefined) {
      return { ok: false, error: "class not found" };
    }

    const chain: string[] = [];
    let current: ObjC.Object | null = cls;
    while (current !== null) {
      chain.push(current.$className);
      current = current.$superClass;
    }

    return {
      ok: true,
      name,
      chain,
      methods: cls.$ownMethods,
      protocols: cls.$protocols,
    };
  },

  disassembleMethod(
    className: string,
    selector: string,
    count: number,
  ): Record<string, unknown> {
    const cls = ObjC.classes[className];
    if (cls === undefined) {
      return { ok: false, error: "class not found" };
    }
    const method = cls[selector];
    if (method === undefined) {
      return { ok: false, error: "method not found" };
    }

    const start = method.implementation;
    let cursor = start;
    const instructions: Array<Record<string, unknown>> = [];
    for (let index = 0; index < Math.max(1, Math.min(count, 500)); index += 1) {
      const instruction = Instruction.parse(cursor);
      let branchTarget: string | null = null;
      let branchSymbol: string | null = null;
      const targetMatch = instruction.opStr.match(/#?(0x[0-9a-f]+)/i);
      if (
        targetMatch !== null &&
        /^(b|bl|cbz|cbnz|tbz|tbnz)\b/.test(instruction.mnemonic)
      ) {
        try {
          const target = ptr(targetMatch[1]);
          branchTarget = target.toString();
          branchSymbol = DebugSymbol.fromAddress(target).name;
        } catch {}
      }
      instructions.push({
        address: instruction.address.toString(),
        mnemonic: instruction.mnemonic,
        operands: instruction.opStr,
        branchTarget,
        branchSymbol,
      });
      cursor = instruction.next;
    }
    return {
      ok: true,
      className,
      selector,
      implementation: start.toString(),
      instructions,
    };
  },

  choose(name: string, limit: number): Record<string, unknown> {
    const cls = ObjC.classes[name];
    if (cls === undefined) {
      return { ok: false, error: "class not found" };
    }

    const matches = ObjC.chooseSync({ class: cls }).slice(0, limit);
    return {
      ok: true,
      count: matches.length,
      objects: matches.map((obj) => {
        const ivars: Record<string, unknown> = {};
        for (const [ivarName, value] of Object.entries(obj.$ivars)) {
          if (
            value === null ||
            typeof value === "number" ||
            typeof value === "boolean" ||
            typeof value === "string"
          ) {
            ivars[ivarName] = value;
          } else {
            ivars[ivarName] = String(value);
          }
        }
        return { className: obj.$className, ivars };
      }),
    };
  },

  snapshot(name: string, limit: number): Record<string, unknown> {
    const cls = ObjC.classes[name];
    if (cls === undefined) {
      return { ok: false, error: "class not found" };
    }

    const matches = ObjC.chooseSync({ class: cls }).slice(0, limit);
    return {
      ok: true,
      count: matches.length,
      objects: matches.map((obj) => {
        const result: Record<string, unknown> = {
          className: obj.$className,
          ivarNames: Object.keys(obj.$ivars),
        };

        try {
          const msgKey = obj.msgKey();
          result.msgKey = msgKey === null ? null : String(msgKey);
        } catch {}
        try {
          result.isSelf = Boolean(obj.amISender());
        } catch {}
        try {
          result.isAtMe = Boolean(obj.isAtMeMessage());
        } catch {}
        try {
          result.isAtAll = Boolean(obj.isAtAllMessage());
        } catch {}
        try {
          result.type = Number(obj.type());
        } catch {}
        try {
          const text = obj.text();
          result.textLength = text === null ? null : String(text).length;
        } catch {}
        try {
          const date = obj.date();
          result.date = date === null ? null : String(date);
        } catch {}
        try {
          const conv = obj.attachConv();
          if (conv !== null) {
            result.conversation = {
              className: conv.$className,
              id: String(conv.conversationId()),
              name: String(conv.name()),
              isOuterGroup: Boolean(conv.isOuterGroupConversation()),
              isWeChatCustomer: Boolean(conv.isWeChatWorkCustomerConversation()),
            };
          }
        } catch {}
        return result;
      }),
    };
  },

  findSelectors(patternSource: string, classPatternSource = ".*"): Record<string, unknown> {
    const selectorPattern = new RegExp(patternSource, "i");
    const classPattern = new RegExp(classPatternSource);
    const classesByModule = ObjC.enumerateLoadedClassesSync();
    const classes = Object.values(classesByModule).flat();
    const matches: Array<{ className: string; selector: string; type: string }> = [];

    for (const className of classes) {
      if (!classPattern.test(className)) {
        continue;
      }
      const cls = ObjC.classes[className];
      if (cls === undefined) {
        continue;
      }
      for (const selector of cls.$ownMethods) {
        if (!selectorPattern.test(selector)) {
          continue;
        }
        try {
          const method = cls[selector];
          matches.push({
            className,
            selector,
            type: method === undefined ? "" : String(method.types),
          });
        } catch {
          matches.push({ className, selector, type: "" });
        }
      }
      if (matches.length >= 500) {
        break;
      }
    }

    return { ok: true, matches };
  },

  listConversations(filterType: number, limit: number): Record<string, unknown> {
    const cls = ObjC.classes.WEWConversationService;
    if (cls === undefined) {
      return { ok: false, error: "WEWConversationService not found" };
    }
    const services = ObjC.chooseSync({ class: cls });
    if (services.length === 0) {
      return { ok: false, error: "service instance not found" };
    }

    try {
      const conversations = services[0].fetchAllConversationsWithFilterType_(
        filterType,
      );
      if (conversations === null || conversations === undefined) {
        return { ok: true, count: 0, conversations: [] };
      }
      const count = Number(conversations.count());
      const payload: Payload[] = [];
      for (let index = 0; index < Math.min(count, limit); index += 1) {
        payload.push(
          conversationPayload(conversations.objectAtIndex_(index)),
        );
      }
      return {
        ok: true,
        filterType,
        count,
        conversations: payload,
      };
    } catch (error) {
      return { ok: false, error: String(error) };
    }
  },

  inspectConversation(conversationId: string): Record<string, unknown> {
    const cls = ObjC.classes.WEWConversationService;
    if (cls === undefined) {
      return { ok: false, error: "WEWConversationService not found" };
    }
    const services = ObjC.chooseSync({ class: cls });
    for (const service of services) {
      try {
        const conversation = service.conversationWithId_(conversationId);
        if (
          conversation !== null &&
          conversation !== undefined
        ) {
          return {
            ok: true,
            conversation: conversationPayload(conversation),
          };
        }
      } catch {}
    }
    return { ok: false, error: "conversation not found" };
  },

  fetchMessages(
    conversationId: string,
    count: number,
    includeText: boolean,
  ): Promise<Record<string, unknown>> {
    return new Promise((resolve) => {
      try {
        const cls = ObjC.classes.WEWMessageService;
        if (cls === undefined) {
          resolve({ ok: false, error: "WEWMessageService not found" });
          return;
        }
        const services = ObjC.chooseSync({ class: cls });
        if (services.length === 0) {
          resolve({ ok: false, error: "service instance not found" });
          return;
        }
        if ((ObjC as any).Block === undefined) {
          resolve({ ok: false, error: "ObjC.Block unavailable" });
          return;
        }

        const callback = new ObjC.Block({
          retType: "void",
          argTypes: ["object"],
          implementation(messages: any) {
            try {
              if (messages === null || messages === undefined) {
                resolve({ ok: true, count: 0, messages: [] });
                return;
              }
              const result = messages;
              const succeeded = readBool(result, "isSucceeded");
              const error = readString(
                result,
                "error" as never,
              );
              const responseData = result.data();
              if (responseData === null || responseData === undefined) {
                resolve({
                  ok: Boolean(succeeded),
                  count: 0,
                  messages: [],
                  error,
                });
                return;
              }
              let data = responseData;
              if (typeof responseData.objectForKey_ === "function") {
                data = responseData.objectForKey_("WEWMessageListKey");
              }
              if (data === null || data === undefined) {
                resolve({
                  ok: Boolean(succeeded),
                  count: 0,
                  messages: [],
                  error,
                });
                return;
              }
              if (typeof data.count !== "function") {
                resolve({
                  ok: false,
                  error: `unexpected callback data: ${String(
                    data.$className ?? typeof data,
                  )}`,
                });
                return;
              }
              if (typeof data.objectAtIndex_ !== "function") {
                resolve({
                  ok: false,
                  error: `callback data is not an array: ${String(
                    data.$className ?? typeof data,
                  )}`,
                  count: Number(data.count()),
                });
                return;
              }
              const messageCount = Number(data.count());
              const payload: Payload[] = [];
              for (
                let index = 0;
                index < Math.min(messageCount, count);
                index += 1
              ) {
                const message = data.objectAtIndex_(index);
                if (message.$className === "WEWMessage") {
                  payload.push(wewMessagePayload(message, includeText));
                } else {
                  payload.push(messagePayload(message, includeText));
                }
              }
              resolve({
                ok: Boolean(succeeded),
                count: messageCount,
                messages: payload,
                error,
              });
            } catch (error) {
              resolve({
                ok: false,
                error: String(error),
                stack: error instanceof Error ? error.stack : null,
              });
            }
          },
        });

        const methodName =
          "fetchConversationMessages_messageId_count_callback_";
        if (typeof (services[0] as any)[methodName] !== "function") {
          resolve({
            ok: false,
            error: "fetch method missing",
            methodName,
            available: Object.keys(services[0]).filter((name) =>
              name.includes("fetchConversation"),
            ),
          });
          return;
        }
        services[0].fetchConversationMessages_messageId_count_callback_(
          conversationId,
          0,
          count,
          callback,
        );
      } catch (error) {
        resolve({ ok: false, error: String(error) });
      }
    });
  },
};
