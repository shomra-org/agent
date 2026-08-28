export const SHOMRA_REFUSED = -32001;

export function safeJson(value) {
  if (value == null) return '';
  try {
    const text = JSON.stringify(value);
    return text.length > 20000 ? text.slice(0, 20000) : text;
  } catch {
    return '';
  }
}

export function createLineFramer(onMessage) {
  let buffer = '';
  return (chunk) => {
    buffer += chunk.toString('utf8');
    let newline = buffer.indexOf('\n');
    while (newline !== -1) {
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      newline = buffer.indexOf('\n');
      if (!line) continue;
      try {
        onMessage(JSON.parse(line), line);
      } catch {
        onMessage(null, line);
      }
    }
  };
}

export function writeMessage(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

export function refusal(id, message, data) {
  return { jsonrpc: '2.0', id, error: { code: SHOMRA_REFUSED, message, data } };
}

export function sendBlockedInitialize(reason, server, verdict) {
  writeMessage(refusal(0, reason, {
    source: 'shomra-mcp-shim',
    server,
    refusedBy: 'policy',
    ...(verdict?.state ? { state: verdict.state } : {}),
    ...(verdict?.eventId ? { eventId: verdict.eventId } : {}),
  }));
}
