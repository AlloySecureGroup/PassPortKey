// Shared helpers for the popup and the approval window.

/** Send a message to the background worker and unwrap { ok, data, error }. */
export async function call(type, extra) {
  const res = await chrome.runtime.sendMessage(Object.assign({ type }, extra));
  if (!res || !res.ok) throw new Error((res && res.error) || 'No response from the extension');
  return res.data;
}

/** Tiny DOM builder. Text is always set as text, never as HTML. */
export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

export function field(label, input) {
  return h('label', { class: 'field' }, h('span', { class: 'label' }, label), input);
}

export function fmtDate(ms) {
  return new Date(ms).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function fmtAgo(ms) {
  if (!ms) return 'never';
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + ' min ago';
  if (s < 86400) return Math.floor(s / 3600) + ' h ago';
  return fmtDate(ms);
}

export function logo() {
  return h('div', { class: 'brand' }, h('img', { src: 'icons/icon32.png', width: 22, height: 22, alt: '' }), h('span', null, 'PassportKey'));
}
