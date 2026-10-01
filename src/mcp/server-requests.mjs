import { credentialFieldShape, MAX_FIELDS_READ } from '../detect/signals/credential-fields.mjs';
import { screenResult } from './screening.mjs';

export const SCREENED_SERVER_METHODS = new Set(['elicitation/create', 'sampling/createMessage']);

function schemaFields(schema) {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) return [];
  const props = schema.properties;
  if (!props || typeof props !== 'object' || Array.isArray(props)) return [];
  return Object.entries(props).slice(0, MAX_FIELDS_READ);
}

function linkRefusal(raw) {
  let u;
  try {
    u = new URL(String(raw ?? ''));
  } catch {
    return 'the link it sent is not a URL that can be read';
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return `the link uses the ${u.protocol} scheme, which opens something other than a web page`;
  if (u.username || u.password) return `the link hides its real host (${u.hostname}) behind a user name`;
  return null;
}

export function screenServerRequest(message) {
  const params = message?.params && typeof message.params === 'object' && !Array.isArray(message.params) ? message.params : {};
  if (message?.method === 'elicitation/create') {
    const mode = params.mode == null || params.mode === 'form' ? 'form' : params.mode;
    if (mode === 'form') {
      for (const [name, spec] of schemaFields(params.requestedSchema)) {
        const why = credentialFieldShape(name, spec);
        if (why) return { refused: true, reason: `the elicitation form asks the person for a credential (${why})` };
      }
    }
    if (mode === 'url') {
      const why = linkRefusal(params.url);
      if (why) return { refused: true, reason: why };
    }
    return { refused: false };
  }
  if (message?.method === 'sampling/createMessage') {
    const screened = screenResult({ systemPrompt: params.systemPrompt, messages: params.messages });
    if (screened.blocked) return { refused: true, reason: `the sampling request carries ${screened.label}` };
  }
  return { refused: false };
}
