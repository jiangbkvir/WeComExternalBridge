import ObjC from "frida-objc-bridge";

type Payload = Record<string, unknown>;

const installedSelectors: string[] = [];
const conversationCache = new Map<string, any>();

type PollCallbackState = {
  block: any;
  handler: ((response: any) => void) | null;
};

const pollCallbackStates = new Map<string, PollCallbackState>();
const sendCallbackStates = new Map<
  string,
  { block: any; count: number; lastResponse: Payload | null }
>();

function hasMethod(className: string, selector: string): boolean {
  const cls = ObjC.classes[className];
  if (cls === undefined) {
    return false;
  }
  return (cls.$methods as string[]).includes(selector);
}

function pollCallbackState(groupId: string): PollCallbackState {
  const existing = pollCallbackStates.get(groupId);
  if (existing !== undefined) {
    return existing;
  }

  let state: PollCallbackState;
  const block = new ObjC.Block({
    retType: "void",
    argTypes: ["object"],
    implementation(response: any) {
      const handler = state.handler;
      state.handler = null;
      if (handler !== null) {
        handler(response);
      }
    },
  });
  state = { block, handler: null };
  pollCallbackStates.set(groupId, state);
  return state;
}

function sendCallbackState(requestId: string): {
  block: any;
  count: number;
  lastResponse: Payload | null;
} {
  const existing = sendCallbackStates.get(requestId);
  if (existing !== undefined) {
    return existing;
  }
  const state: {
    block: any;
    count: number;
    lastResponse: Payload | null;
  } = {
    block: null,
    count: 0,
    lastResponse: null,
  };
  state.block = new ObjC.Block({
    retType: "void",
    argTypes: ["object"],
    implementation(response: any) {
      state.count += 1;
      const payload: Payload = {
        className:
          response === null || response === undefined
            ? null
            : String(response.$className),
        succeeded:
          response === null || response === undefined
            ? null
            : readBool(response, "isSucceeded"),
        error:
          response === null || response === undefined
            ? null
            : readString(response, "errorMessage"),
      };
      state.lastResponse = payload;
    },
  });
  sendCallbackStates.set(requestId, state);
  if (sendCallbackStates.size > 100) {
    const oldest = sendCallbackStates.keys().next().value;
    if (oldest !== undefined && oldest !== requestId) {
      sendCallbackStates.delete(oldest);
    }
  }
  return state;
}

type ProtoField = {
  number: number;
  wire: number;
  value: number | Uint8Array;
};

type ParsedMessageContent = {
  text: string;
  mentions: string[];
  mentionNames: string[];
  itemTypes: number[];
};

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
    const value = obj[selector]();
    return value === null || value === undefined ? null : Number(value);
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

function readNSData(data: any, maxBytes = 65536): Uint8Array | null {
  if (data === null || data === undefined) {
    return null;
  }
  try {
    const length = Number(data.length());
    if (
      !Number.isFinite(length) ||
      length <= 0 ||
      length > maxBytes
    ) {
      return null;
    }
    const bytes = data.bytes().readByteArray(length);
    return bytes === null ? null : new Uint8Array(bytes);
  } catch {
    return null;
  }
}

function nsDataHexPrefix(data: any, maxBytes = 64): string | null {
  const bytes = readNSData(data, maxBytes);
  if (bytes === null) {
    return null;
  }
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function readVarint(
  data: Uint8Array,
  offset: number,
): [number, number] | null {
  let value = 0;
  let shift = 0;
  let index = offset;
  while (index < data.length && shift <= 56) {
    const byte = data[index];
    index += 1;
    value += (byte & 0x7f) * 2 ** shift;
    if ((byte & 0x80) === 0) {
      return [value, index];
    }
    shift += 7;
  }
  return null;
}

function parseProtoFields(data: Uint8Array): ProtoField[] {
  const fields: ProtoField[] = [];
  let offset = 0;
  while (offset < data.length) {
    const tag = readVarint(data, offset);
    if (tag === null) {
      break;
    }
    const tagValue = tag[0];
    offset = tag[1];
    const fieldNumber = Math.floor(tagValue / 8);
    const wire = tagValue & 0x07;
    if (fieldNumber <= 0) {
      break;
    }
    if (wire === 0) {
      const scalar = readVarint(data, offset);
      if (scalar === null) {
        break;
      }
      fields.push({ number: fieldNumber, wire, value: scalar[0] });
      offset = scalar[1];
      continue;
    }
    if (wire === 1) {
      if (offset + 8 > data.length) {
        break;
      }
      fields.push({
        number: fieldNumber,
        wire,
        value: data.slice(offset, offset + 8),
      });
      offset += 8;
      continue;
    }
    if (wire === 2) {
      const lengthValue = readVarint(data, offset);
      if (lengthValue === null) {
        break;
      }
      const length = lengthValue[0];
      offset = lengthValue[1];
      if (
        !Number.isFinite(length) ||
        length < 0 ||
        offset + length > data.length
      ) {
        break;
      }
      fields.push({
        number: fieldNumber,
        wire,
        value: data.slice(offset, offset + length),
      });
      offset += length;
      continue;
    }
    if (wire === 5) {
      if (offset + 4 > data.length) {
        break;
      }
      fields.push({
        number: fieldNumber,
        wire,
        value: data.slice(offset, offset + 4),
      });
      offset += 4;
      continue;
    }
    break;
  }
  return fields;
}

function decodeUtf8(data: Uint8Array): string {
  const codeUnits: number[] = [];
  let index = 0;
  while (index < data.length) {
    const first = data[index];
    index += 1;
    let codePoint = 0xfffd;
    if (first < 0x80) {
      codePoint = first;
    } else if (first >= 0xc2 && first <= 0xdf && index < data.length) {
      const second = data[index];
      if ((second & 0xc0) === 0x80) {
        index += 1;
        codePoint = ((first & 0x1f) << 6) | (second & 0x3f);
      }
    } else if (
      first >= 0xe0 &&
      first <= 0xef &&
      index + 1 < data.length
    ) {
      const second = data[index];
      const third = data[index + 1];
      if (
        (second & 0xc0) === 0x80 &&
        (third & 0xc0) === 0x80
      ) {
        index += 2;
        codePoint =
          ((first & 0x0f) << 12) |
          ((second & 0x3f) << 6) |
          (third & 0x3f);
      }
    } else if (
      first >= 0xf0 &&
      first <= 0xf4 &&
      index + 2 < data.length
    ) {
      const second = data[index];
      const third = data[index + 1];
      const fourth = data[index + 2];
      if (
        (second & 0xc0) === 0x80 &&
        (third & 0xc0) === 0x80 &&
        (fourth & 0xc0) === 0x80
      ) {
        index += 3;
        codePoint =
          ((first & 0x07) << 18) |
          ((second & 0x3f) << 12) |
          ((third & 0x3f) << 6) |
          (fourth & 0x3f);
      }
    }

    if (codePoint <= 0xffff) {
      codeUnits.push(codePoint);
    } else {
      const adjusted = codePoint - 0x10000;
      codeUnits.push(
        0xd800 + (adjusted >> 10),
        0xdc00 + (adjusted & 0x3ff),
      );
    }
  }

  let result = "";
  for (let index = 0; index < codeUnits.length; index += 4096) {
    result += String.fromCharCode(...codeUnits.slice(index, index + 4096));
  }
  return result;
}

function protoBytes(field: ProtoField | undefined): Uint8Array | null {
  return field !== undefined && field.wire === 2
    ? (field.value as Uint8Array)
    : null;
}

function protoNumber(field: ProtoField | undefined): number | null {
  return field !== undefined && field.wire === 0
    ? Number(field.value)
    : null;
}

function parseMessageContent(data: Uint8Array): ParsedMessageContent {
  const result: ParsedMessageContent = {
    text: "",
    mentions: [],
    mentionNames: [],
    itemTypes: [],
  };
  const textParts: string[] = [];

  for (const outerField of parseProtoFields(data)) {
    if (outerField.number !== 5 || outerField.wire !== 2) {
      continue;
    }
    const envelopeFields = parseProtoFields(
      outerField.value as Uint8Array,
    );
    for (const envelopeField of envelopeFields) {
      if (envelopeField.number !== 1 || envelopeField.wire !== 2) {
        continue;
      }
      const itemFields = parseProtoFields(
        envelopeField.value as Uint8Array,
      );
      const itemType = protoNumber(
        itemFields.find((field) => field.number === 1 && field.wire === 0),
      );
      const payload = protoBytes(
        itemFields.find((field) => field.number === 2 && field.wire === 2),
      );
      if (itemType === null || payload === null) {
        continue;
      }
      result.itemTypes.push(itemType);
      const payloadFields = parseProtoFields(payload);

      if (itemType === 0) {
        for (const field of payloadFields) {
          if (field.number === 1 && field.wire === 2) {
            textParts.push(decodeUtf8(field.value as Uint8Array));
          }
        }
        continue;
      }

      if (itemType === 10) {
        const targetId = protoNumber(
          payloadFields.find(
            (field) => field.number === 1 && field.wire === 0,
          ),
        );
        const targetName = protoBytes(
          payloadFields.find(
            (field) => field.number === 2 && field.wire === 2,
          ),
        );
        if (targetId !== null) {
          result.mentions.push(String(targetId));
        }
        if (targetName !== null) {
          result.mentionNames.push(decodeUtf8(targetName));
        }
      }
    }
  }

  result.text = textParts.join("");
  return result;
}

function cacheConversation(conversation: any): void {
  const conversationId = readString(conversation, "conversationId");
  if (!conversationId) {
    return;
  }
  try {
    const retained = conversation.retain();
    const previous = conversationCache.get(conversationId);
    conversationCache.set(conversationId, retained);
    if (previous !== undefined && previous !== retained) {
      try {
        previous.release();
      } catch {}
    }
  } catch {}
}

function pollingMessagePayload(
  message: any,
  conversationData: Payload,
  botUserId: string,
): Payload | null {
  const messageId = readString(message, "messageId");
  if (!messageId) {
    return null;
  }
  const senderId = readString(message, "senderId") ?? "";
  const contentType = readNumber(message, "contentType");
  const rawContent = readNSData(message.content());
  const parsed: ParsedMessageContent =
    contentType !== 1 || rawContent === null
      ? { text: "", mentions: [], mentionNames: [], itemTypes: [] }
      : parseMessageContent(rawContent);
  const sendTime = readNumber(message, "sendTime");
  const timestamp =
    sendTime !== null && sendTime > 1_000_000_000
      ? sendTime
      : Math.floor(Date.now() / 1000);
  const isSelf =
    botUserId !== "" &&
    senderId === botUserId;

  return {
    msgKey: messageId,
    messageId,
    serverId: readString(message, "serverId"),
    clientId: readString(message, "clientId"),
    contentType,
    cppContentType: readNumber(message, "cppContentType"),
    isSelf,
    isAtMe:
      botUserId !== "" && parsed.mentions.includes(botUserId),
    isAtAll: false,
    type: readNumber(message, "contentType"),
    text: parsed.text,
    timestamp,
    sender: {
      className: "WEWMessage",
      id: senderId || null,
      name:
        readString(message, "senderName") ||
        readString(message, "realSenderName"),
      realName: readString(message, "realSenderName"),
    },
    conversation: conversationData,
    mentions: parsed.mentions,
    mentionNames: parsed.mentionNames,
    items: parsed.itemTypes,
  };
}

function performNativeSend(
  groupId: string,
  text: string,
  requestId: string,
): Payload {
  const conversationId = String(groupId);
  const messageText = String(text);
  if (conversationId === "" || messageText.length === 0) {
    return { ok: false, error: "invalid send request" };
  }
  const messageServiceCls = ObjC.classes.WEWMessageService;
  const mediaCls = ObjC.classes.WEWMultiMediaObject;
  if (
    messageServiceCls === undefined ||
    mediaCls === undefined
  ) {
    return { ok: false, error: "native send classes unavailable" };
  }
  const messageServices = ObjC.chooseSync({ class: messageServiceCls });
  if (messageServices.length === 0) {
    return { ok: false, error: "native send services unavailable" };
  }

  const media = mediaCls.alloc().init();
  if (media === null || media === undefined) {
    return { ok: false, error: "media object init returned nil" };
  }
  media.addText_isNeedConfirm_(messageText, false);
  const count = Number(media.mediaObjectCount());
  const content = media.getContent();
  const contentLength =
    content === null || content === undefined ? 0 : Number(content.length());
  if (count < 1 || contentLength < 1) {
    return { ok: false, error: "media object content is empty" };
  }
  const stringCls = ObjC.classes.NSString;
  if (stringCls === undefined) {
    return { ok: false, error: "NSString unavailable" };
  }
  const nativeConversationId =
    stringCls.stringWithString_(conversationId);
  if (
    nativeConversationId === null ||
    nativeConversationId === undefined
  ) {
    return { ok: false, error: "conversation id conversion failed" };
  }
  const callback = sendCallbackState(String(requestId));

  const objcMsgSend = new NativeFunction(
    Module.getGlobalExportByName("objc_msgSend"),
    "void",
    ["pointer", "pointer", "pointer", "uint8", "pointer", "pointer"],
  );
  objcMsgSend(
    messageServices[0].handle,
    ObjC.selector(
      "sendMultiMediaMessage:isAnonymity:toConversation:resultCallback:",
    ),
    media.handle,
    0,
    nativeConversationId.handle,
    callback.block.handle,
  );
  return {
    ok: true,
    groupId: conversationId,
    requestId: String(requestId),
    textLength: messageText.length,
    mediaObjectCount: count,
    contentLength,
    accepted: true,
    callbackCount: callback.count,
    callbackResponse: callback.lastResponse,
  };
}

function diagnoseSendContract(groupId: string): Payload {
  const cls = ObjC.classes.WEWMessageService;
  if (cls === undefined) {
    return { ok: false, error: "WEWMessageService not found" };
  }
  const selector =
    "- sendMultiMediaMessage:isAnonymity:toConversation:resultCallback:";
  const method = (cls as any)[selector];
  if (method === undefined) {
    return { ok: false, error: "send method not found" };
  }

  const implementation = method.implementation;
  const instructions: Payload[] = [];
  let disassemblyError: string | null = null;
  try {
    let cursor = implementation;
    for (let index = 0; index < 160; index += 1) {
      const instruction = Instruction.parse(cursor);
      let target: string | null = null;
      let symbol: string | null = null;
      const targetMatch = instruction.opStr.match(/#?(0x[0-9a-f]+)/i);
      if (
        targetMatch !== null &&
        /^(b|bl|cbz|cbnz|tbz|tbnz)\b/.test(instruction.mnemonic)
      ) {
        try {
          const branchTarget = ptr(targetMatch[1]);
          target = branchTarget.toString();
          symbol = DebugSymbol.fromAddress(branchTarget).name;
        } catch {}
      }
      instructions.push({
        address: instruction.address.toString(),
        mnemonic: instruction.mnemonic,
        operands: instruction.opStr,
        target,
        symbol,
      });
      cursor = instruction.next;
    }
  } catch (error) {
    disassemblyError = String(error);
  }

  const conversationCls = ObjC.classes.WEWConversation;
  const stringCls = ObjC.classes.NSString;
  const conversationMethods =
    conversationCls === undefined
      ? []
      : (conversationCls.$methods as string[]).filter((name) =>
          /fox|cpp|conversationId/i.test(name),
        );
  const stringMethods =
    stringCls === undefined
      ? []
      : (stringCls.$methods as string[]).filter((name) =>
          /foxCppString|cppString/i.test(name),
        );
  return {
    ok: true,
    groupId: String(groupId),
    implementation: implementation.toString(),
    types: method.types ?? null,
    disassemblyError,
    instructions,
    hasFoxCppStringOnConversation:
      hasMethod("WEWConversation", "- foxCppString"),
    hasFoxCppStringOnNSString:
      hasMethod("NSString", "- foxCppString"),
    conversationMethods,
    stringMethods,
  };
}

rpc.exports = {
  health(): Payload {
    return {
      ok: true,
      installedSelectors,
      cachedConversationCount: conversationCache.size,
      hasRichTextEncoder: hasMethod(
        "WEWRichTextEncoder",
        "+ wew_encodeTextMsg:extraData:insertLimitStr:",
      ),
      hasMediaObjectInit: hasMethod(
        "WEWMultiMediaObject",
        "- init",
      ),
      hasMediaObjectAddText: hasMethod(
        "WEWMultiMediaObject",
        "- addText:isNeedConfirm:",
      ),
      hasMessageServiceSend: hasMethod(
        "WEWMessageService",
        "- sendMultiMediaMessage:isAnonymity:toConversation:resultCallback:",
      ),
      hasForwardTextHelper:
        ObjC.classes.WEWForwardMessageHelper !== undefined &&
        ObjC.classes.WEWForwardMessageHelper[
          "+ forwardTextAsMessage:formConv:"
        ] !== undefined,
      nativeSendBackend: "native_message_service",
    };
  },

  diagnoseEncoder(text: string): Payload {
    const value = String(text);
    if (value.length === 0 || value.length > 4000) {
      return { ok: false, error: "invalid text length" };
    }
    const cls = ObjC.classes.WEWRichTextEncoder;
    if (cls === undefined) {
      return { ok: false, error: "WEWRichTextEncoder not found" };
    }
    let limitReached: any = null;
    try {
      limitReached = Memory.alloc(1);
      limitReached.writeU8(0);
      const encode = (cls as any)[
        "+ wew_encodeTextMsg:extraData:insertLimitStr:"
      ];
      if (typeof encode !== "function") {
        return { ok: false, error: "encoder class method unavailable" };
      }
      const encoded = encode.call(
        cls,
        value,
        null,
        limitReached,
      );
      const encodedLength =
        encoded === null || encoded === undefined
          ? null
          : Number(encoded.length());
      return {
        ok: encodedLength !== null && encodedLength > 0,
        className:
          encoded === null || encoded === undefined
            ? null
            : String(encoded.$className),
        encodedLength,
        encodedHexPrefix: nsDataHexPrefix(encoded),
        limitReached: Boolean(limitReached.readU8()),
        error:
          encodedLength !== null && encodedLength > 0
            ? null
            : "encoder returned empty content",
      };
    } catch (error) {
      return { ok: false, error: String(error) };
    }
  },

  diagnoseMediaObject(text: string): Payload {
    const value = String(text);
    if (value.length === 0 || value.length > 4000) {
      return { ok: false, error: "invalid text length" };
    }
    const cls = ObjC.classes.WEWMultiMediaObject;
    if (cls === undefined) {
      return { ok: false, error: "WEWMultiMediaObject not found" };
    }
    try {
      const media = cls.alloc().init();
      if (media === null || media === undefined) {
        return { ok: false, error: "media object init returned nil" };
      }
      const added = media.addText_isNeedConfirm_(value, false);
      const count = Number(media.mediaObjectCount());
      const content = media.getContent();
      const rawContent = media.rawContent();
      const extraContent = media.extraContent();
      return {
        ok: count > 0,
        className: String(media.$className),
        addedClassName:
          added === null || added === undefined
            ? null
            : String(added.$className),
        mediaObjectCount: count,
        getContentClass:
          content === null || content === undefined
            ? null
            : String(content.$className),
        getContentLength:
          content === null || content === undefined
            ? null
            : Number(content.length?.() ?? 0),
        getContentHexPrefix: nsDataHexPrefix(content),
        rawContentClass:
          rawContent === null || rawContent === undefined
            ? null
            : String(rawContent.$className),
        rawContentLength:
          rawContent === null || rawContent === undefined
            ? null
            : Number(rawContent.length?.() ?? 0),
        extraContentClass:
          extraContent === null || extraContent === undefined
            ? null
            : String(extraContent.$className),
        extraContentLength:
          extraContent === null || extraContent === undefined
            ? null
            : Number(extraContent.length?.() ?? 0),
      };
    } catch (error) {
      return { ok: false, error: String(error) };
    }
  },

  diagnoseSendContract(groupId: string): Payload {
    return diagnoseSendContract(String(groupId));
  },

  parseContentHex(contentHex: string): Payload {
    const clean = String(contentHex).replace(/[^0-9a-f]/gi, "");
    if (clean.length === 0 || clean.length % 2 !== 0) {
      return { ok: false, error: "invalid content hex" };
    }
    const data = new Uint8Array(clean.length / 2);
    for (let index = 0; index < data.length; index += 1) {
      data[index] = parseInt(clean.slice(index * 2, index * 2 + 2), 16);
    }
    return { ok: true, parsed: parseMessageContent(data) };
  },

  pollMessages(
    groupIds: string[],
    botUserId: string,
    count: number,
    knownMessageIds: Payload,
  ): Promise<Payload> {
    return new Promise((resolve) => {
      const safeGroupIds = Array.isArray(groupIds)
        ? groupIds
            .map((value) => String(value))
            .filter((value) => value !== "")
            .slice(0, 20)
        : [];
      const safeCount = Math.max(1, Math.min(Number(count) || 30, 100));
      const cls = ObjC.classes.WEWMessageService;
      if (cls === undefined) {
        resolve({ ok: false, error: "WEWMessageService not found" });
        return;
      }
      const services = ObjC.chooseSync({ class: cls });
      if (services.length === 0) {
        resolve({ ok: false, error: "message service instance not found" });
        return;
      }
      if ((ObjC as any).Block === undefined) {
        resolve({ ok: false, error: "ObjC.Block unavailable" });
        return;
      }

      const conversationCls = ObjC.classes.WEWConversationService;
      const conversationServices =
        conversationCls === undefined
          ? []
          : ObjC.chooseSync({ class: conversationCls });
      const service = services[0];
      const conversationService = conversationServices[0];
      const knownByGroup: Record<string, string> =
        knownMessageIds !== null &&
        typeof knownMessageIds === "object"
          ? (knownMessageIds as Record<string, string>)
          : {};
      const messages: Payload[] = [];
      const errors: string[] = [];
      let activeCallback: PollCallbackState | null = null;
      const startedAt = Date.now();
      let callbackCount = 0;
      let timedOut = false;
      let finished = false;

      const finish = (): void => {
        if (finished) {
          return;
        }
        finished = true;
        if (activeCallback !== null) {
          activeCallback.handler = null;
        }
        resolve({
          ok: errors.length === 0,
          groups: safeGroupIds.length,
          count: messages.length,
          messages,
          errors,
          callbackCount,
          timedOut,
          durationMs: Date.now() - startedAt,
          serviceCount: services.length,
        });
      };
      const timer = setTimeout(() => {
        timedOut = true;
        finish();
      }, 8000);
      const finishAndClear = (): void => {
        clearTimeout(timer);
        finish();
      };

      const fetchAt = (index: number): void => {
        if (index >= safeGroupIds.length) {
          finishAndClear();
          return;
        }
        const groupId = safeGroupIds[index];
        let conversation: any = null;
        try {
          conversation =
            conversationService?.conversationWithId_(groupId) ?? null;
        } catch {}
        if (conversation === null || conversation === undefined) {
          errors.push(`conversation unavailable: ${groupId}`);
          fetchAt(index + 1);
          return;
        }
        cacheConversation(conversation);
        const conversationData = conversationPayload(conversation);
        const knownMessageId = String(knownByGroup[groupId] ?? "");
        const callbackState = pollCallbackState(groupId);
        if (callbackState.handler !== null) {
          errors.push(`fetch already active: ${groupId}`);
          fetchAt(index + 1);
          return;
        }
        activeCallback = callbackState;
        callbackState.handler = (response: any) => {
          callbackCount += 1;
          try {
            const succeeded = readBool(response, "isSucceeded");
            const responseData = response?.data?.() ?? null;
            let data = responseData;
            if (
              responseData !== null &&
              responseData !== undefined &&
              typeof responseData.objectForKey_ === "function"
            ) {
              data =
                responseData.objectForKey_("WEWMessageListKey") ??
                responseData;
            }
            if (
              data !== null &&
              data !== undefined &&
              typeof data.count === "function" &&
              typeof data.objectAtIndex_ === "function"
            ) {
              const messageCount = Number(data.count());
              const groupMessages: Payload[] = [];
              for (
                let messageIndex = 0;
                messageIndex < Math.min(messageCount, safeCount);
                messageIndex += 1
              ) {
                try {
                  const message = data.objectAtIndex_(messageIndex);
                  if (message?.$className !== "WEWMessage") {
                    continue;
                  }
                  if (
                    knownMessageId !== "" &&
                    readString(message, "messageId") === knownMessageId
                  ) {
                    break;
                  }
                  const payload = pollingMessagePayload(
                    message,
                    conversationData,
                    botUserId,
                  );
                  if (payload !== null) {
                    groupMessages.push(payload);
                  }
                } catch {}
              }
              messages.push(...groupMessages.reverse());
            }
            if (!succeeded) {
              errors.push(`fetch failed: ${groupId}`);
            }
          } catch (error) {
            errors.push(`fetch callback failed: ${groupId}: ${String(error)}`);
          }
          fetchAt(index + 1);
        };

        try {
          service.fetchConversationMessages_messageId_count_callback_(
            groupId,
            0,
            safeCount,
            callbackState.block,
          );
        } catch (error) {
          callbackState.handler = null;
          errors.push(`fetch call failed: ${groupId}: ${String(error)}`);
          fetchAt(index + 1);
        }
      };

      if (safeGroupIds.length === 0) {
        finishAndClear();
        return;
      }
      fetchAt(0);
    });
  },

  peekMessages(
    groupIds: string[],
    botUserId: string,
    count: number,
  ): Promise<Payload> {
    const safeGroupIds = Array.isArray(groupIds)
      ? groupIds
          .map((value) => String(value))
          .filter((value) => value !== "")
          .slice(0, 10)
      : [];
    const safeCount = Math.max(1, Math.min(Number(count) || 20, 100));
    return this.pollMessages(safeGroupIds, botUserId, safeCount, {});
  },

  sendText(
    groupId: string,
    text: string,
    requestId: string,
  ): Promise<Payload> {
    return new Promise((resolve) => {
      try {
        resolve(performNativeSend(groupId, text, requestId));
      } catch (error) {
        resolve({ ok: false, error: String(error) });
      }
    });
  },
};

send({
  kind: "ready",
  message: "native polling installed",
  installedSelectors,
});
