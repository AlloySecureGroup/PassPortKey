// Runs in the isolated world. Relays requests from inject.js (page) to the background worker
// and back. It does no WebAuthn work itself and holds no secrets.

window.addEventListener('message', async (ev) => {
  if (ev.source !== window) return;
  const d = ev.data;
  if (!d || d.channel !== 'passportkey-req' || typeof d.id !== 'string') return;
  if (d.type !== 'wa:create' && d.type !== 'wa:get') return;

  let result = { handled: false };
  try {
    const res = await chrome.runtime.sendMessage({ type: d.type, payload: d.payload });
    if (res && res.ok) result = res.data;
  } catch {
    // Extension reloaded or worker unavailable: let the browser handle it natively.
  }
  window.postMessage({ channel: 'passportkey-res', id: d.id, result }, '*');
});
