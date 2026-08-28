
export function normalizeGuardInput(agent, payload) {
  const norm = normalizeGuardShape(agent, payload);

  const parent = parentSessionFrom(agent, payload);
  return parent ? { ...norm, parent_session_id: parent } : norm;
}

export function parentSessionFrom(agent, payload) {
  const p = payload || {};
  const candidates = [

    p.parent_session_id,
    p.parentSessionId,
    agent === 'cursor' ? p.parent_conversation_id : undefined,
    agent === 'windsurf' ? p.parent_trajectory_id : undefined,
    agent === 'cline' ? p.parent_task_id : undefined,

    process.env.SHOMRA_PARENT_SESSION_ID,
  ];
  const self = String(p.session_id ?? p.conversation_id ?? p.task_id ?? p.trajectory_id ?? '').trim();
  for (const c of candidates) {
    const v = typeof c === 'string' ? c.trim() : '';

    if (v && v.length <= 200 && v !== self) return v;
  }
  return undefined;
}

function normalizeGuardShape(agent, payload) {
  switch (agent) {
    case 'cursor': {
      if (typeof payload.command === 'string') {
        return { tool_name: 'Bash', tool_input: { command: payload.command }, cwd: payload.cwd || payload.workspace_roots?.[0], session_id: payload.conversation_id };
      }
      if (payload.tool_name || payload.tool) {
        const name = payload.tool_name || payload.tool;
        return { tool_name: String(name).startsWith('mcp') ? name : `mcp__${name}`, tool_input: payload.tool_input ?? payload.arguments, tool_response: payload.tool_response ?? payload.result, cwd: payload.cwd, session_id: payload.conversation_id };
      }
      if (typeof payload.file_path === 'string') {
        return { tool_name: 'Edit', tool_input: { file_path: payload.file_path, content: payload.content ?? payload.new_content }, cwd: payload.cwd, session_id: payload.conversation_id };
      }
      return { tool_name: payload.hook_event_name || 'unknown', tool_input: payload, session_id: payload.conversation_id };
    }
    case 'windsurf': {
      const info = payload.tool_info || {};
      if (typeof info.command_line === 'string') return { tool_name: 'Bash', tool_input: { command: info.command_line }, session_id: payload.trajectory_id };
      if (typeof info.file_path === 'string') return { tool_name: 'Edit', tool_input: { file_path: info.file_path, content: info.content }, tool_response: info.result, session_id: payload.trajectory_id };
      return { tool_name: payload.agent_action_name || 'unknown', tool_input: info, tool_response: info.result, session_id: payload.trajectory_id };
    }
    case 'copilot':
      return {
        tool_name: payload.toolName || payload.tool_name,
        tool_input: payload.toolArgs || payload.tool_input,
        tool_response: payload.toolResponse ?? payload.tool_response,
        cwd: payload.cwd,
        session_id: payload.sessionId || payload.session_id,
      };
    case 'cline': {

      const name = payload.tool_name || payload.tool || payload.name;
      const input = payload.tool_input ?? payload.input ?? payload.arguments ?? payload.params;
      if (name === 'use_mcp_tool') {
        const server = payload.server_name || input?.server_name || 'server';
        const mcpTool = input?.tool_name || input?.name || 'tool';
        return { tool_name: `mcp__${server}__${mcpTool}`, tool_input: input?.arguments ?? input, tool_response: payload.tool_response ?? payload.result, cwd: payload.cwd, session_id: payload.task_id || payload.session_id };
      }
      return { tool_name: name, tool_input: input, tool_response: payload.tool_response ?? payload.result, cwd: payload.cwd, session_id: payload.task_id || payload.session_id };
    }
    case 'gemini':
    case 'codex':
    case 'claude':
    case 'aider':
    default:
      return { tool_name: payload.tool_name, tool_input: payload.tool_input, tool_response: payload.tool_response, cwd: payload.cwd, session_id: payload.session_id };
  }
}
