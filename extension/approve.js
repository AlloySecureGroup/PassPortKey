// The approval window. Every passkey operation goes through here, and the site name shown
// comes from the background worker (derived from the real page URL), never from the page.

import { call, h, field, fmtDate, logo } from './ui.js';

const app = document.getElementById('app');
const reqId = new URLSearchParams(location.search).get('req');

// Keep the service worker alive while the person decides.
setInterval(() => call('req:ping').catch(() => {}), 10000);

async function render() {
  let v;
  try {
    v = await call('req:get', { reqId });
  } catch (e) {
    app.replaceChildren(h('div', { class: 'header' }, logo()), h('p', { class: 'error' }, e.message), h('button', { onclick: () => window.close() }, 'Close'));
    return;
  }
  app.replaceChildren(v.locked ? lockedView(v) : choiceView(v));
}

function siteBox(v) {
  return h('div', { class: 'site' }, h('div', { class: 'rp' }, v.rpId), h('div', { class: 'origin' }, v.origin));
}

async function decide(action, extra) {
  await call('req:decide', Object.assign({ reqId, action }, extra));
}

function otherActions(v, err) {
  return [
    h('button', { onclick: () => decide('native').catch((e) => (err.textContent = e.message)) }, 'Use another method'),
    h('button', { class: 'link', onclick: () => decide('cancel').catch(() => window.close()) }, 'Cancel')
  ];
}

function lockedView(v) {
  const err = h('p', { class: 'error', role: 'alert' });
  const pw = h('input', { type: 'password', autocomplete: 'current-password', id: 'pw' });
  const go = h('button', { class: 'primary', type: 'submit' }, 'Unlock');
  const form = h(
    'form',
    {
      onsubmit: async (ev) => {
        ev.preventDefault();
        err.textContent = '';
        go.disabled = true;
        try {
          await call('req:unlock', { reqId, password: pw.value });
          await render();
        } catch (e) {
          err.textContent = e.message;
          go.disabled = false;
          pw.select();
        }
      }
    },
    field('Master password for ' + v.account, pw),
    h('div', { class: 'actions' }, go, ...otherActions(v, err)),
    err
  );
  setTimeout(() => pw.focus(), 0);
  return h(
    'div',
    null,
    h('div', { class: 'header' }, logo()),
    h('h1', null, v.kind === 'create' ? 'Save a passkey' : 'Sign in with a passkey'),
    h('p', { class: 'muted' }, 'Unlock your vault to continue.'),
    siteBox(v),
    form
  );
}

function choiceView(v) {
  const err = h('p', { class: 'error', role: 'alert' });
  const pw = v.needsPassword
    ? h('input', { type: 'password', autocomplete: 'current-password', id: 'pw' })
    : null;

  let chosen = v.credentials.length ? v.credentials[0].id : null;
  let middle;
  let title;
  let confirmLabel;

  if (v.kind === 'create') {
    title = 'Save a passkey';
    confirmLabel = 'Save passkey';
    const who = (v.user && (v.user.displayName || v.user.name)) || 'your account';
    middle = h(
      'div',
      null,
      h('p', null, 'Create a passkey for ', h('strong', null, who), v.user && v.user.name && v.user.displayName ? ' (' + v.user.name + ')' : '', ' on ', h('strong', null, v.rpId), '?'),
      v.credentials.length
        ? h('p', { class: 'notice small' }, 'You already have ' + v.credentials.length + ' passkey' + (v.credentials.length === 1 ? '' : 's') + ' saved for this site.')
        : null
    );
  } else {
    title = 'Sign in with a passkey';
    confirmLabel = 'Continue';
    middle = h(
      'div',
      { role: 'radiogroup', 'aria-label': 'Choose an account' },
      v.credentials.map((c, i) =>
        h(
          'label',
          { class: 'choice' },
          h('input', { type: 'radio', name: 'cred', value: c.id, checked: i === 0, onchange: () => { chosen = c.id; } }),
          h('div', null, h('div', { style: 'font-weight:600' }, c.userName || c.userDisplayName || 'Unnamed account'), h('div', { class: 'small muted' }, 'Added ' + fmtDate(c.createdAt)))
        )
      )
    );
  }

  const go = h('button', { class: 'primary', type: 'submit' }, confirmLabel);
  const form = h(
    'form',
    {
      onsubmit: async (ev) => {
        ev.preventDefault();
        err.textContent = '';
        go.disabled = true;
        try {
          await decide('approve', { credentialId: chosen, password: pw ? pw.value : undefined });
        } catch (e) {
          err.textContent = e.message;
          go.disabled = false;
          if (/locked/i.test(e.message)) await render();
        }
      }
    },
    middle,
    pw ? field('This site requires verification. Enter your master password.', pw) : null,
    h('div', { class: 'actions' }, go, ...otherActions(v, err)),
    err
  );

  return h('div', null, h('div', { class: 'header' }, logo()), h('h1', null, title), siteBox(v), form);
}

render();
