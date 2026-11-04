// VectorDiff do protocolo gerado (src/generated/protocol.ts). Lista própria por subscription.
export function applyDiffs(items, diffs) {
  const next = items.slice();
  for (const d of diffs) {
    switch (d.op) {
      case 'append': next.push(...d.values); break;
      case 'clear': next.length = 0; break;
      case 'push_front': next.unshift(d.value); break;
      case 'push_back': next.push(d.value); break;
      case 'pop_front': next.shift(); break;
      case 'pop_back': next.pop(); break;
      case 'insert': bound(d.index, next.length); next.splice(d.index, 0, d.value); break;
      case 'set': bound(d.index, next.length - 1); next[d.index] = d.value; break;
      case 'remove': bound(d.index, next.length - 1); next.splice(d.index, 1); break;
      case 'truncate': next.length = Math.min(next.length, d.length); break;
      case 'reset': next.splice(0, next.length, ...d.values); break;
      default: throw new Error(`timeline: unknown diff op ${String(d.op).slice(0, 32)}`);
    }
  }
  return next;
}
function bound(index, max) {
  if (!Number.isInteger(index) || index < 0 || index > max) throw new Error('timeline: diff index out of range');
}

const isCanaryMessage = (item, canary) => item?.content?.kind === 'message' && item.content.body === canary;

// Remoto confirmado: event_id do servidor presente; eco local tem event_id null.
export function findConfirmed(items, canary) {
  const hits = items.filter(i => isCanaryMessage(i, canary));
  const confirmed = hits.filter(i => typeof i.event_id === 'string' && i.event_id.startsWith('$')
    && (i.send_state === null || i.send_state?.status === 'sent') && i.is_own === true);
  return confirmed.length === 1 ? confirmed[0] : null;
}

export function findDecrypted(items, eventId, canary) {
  const item = items.find(i => i?.event_id === eventId);
  if (!item) return { ok: false, reason: 'event absent' };
  if (item.content?.kind === 'unable_to_decrypt') return { ok: false, reason: 'unable_to_decrypt' };
  return isCanaryMessage(item, canary) ? { ok: true, item } : { ok: false, reason: `content kind ${String(item.content?.kind).slice(0, 32)}` };
}
