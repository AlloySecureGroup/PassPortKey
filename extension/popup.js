import { call, h, field, fmtDate, fmtAgo, logo } from './ui.js';

const app = document.getElementById('app');
let filter = '';

async function render() {
  let st;
  try {
    st = await call('ui:status');
  } catch (e) {
    app.replaceChildren(logo(), h('p', { class: 'error' }, e.message));
    return;
  }
  if (!st.configured) return app.replaceChildren(setupView());
  if (!st.unlocked) return app.replaceChildren(await lockedView(st));
  app.replaceChildren(await vaultView(st));
}

// ---------- first run ----------

function setupView() {
  let mode = 'create';
  const wrap = h('div');
  const err = h('p', { class: 'error', role: 'alert' });

  function draw() {
    const acct = h('input', { type: 'text', autocomplete: 'username', placeholder: 'you@example.com', id: 'acct' });
    const pw = h('input', { type: 'password', autocomplete: mode === 'create' ? 'new-password' : 'current-password', id: 'pw' });
    const pw2 = h('input', { type: 'password', autocomplete: 'new-password', id: 'pw2' });
    const url = h('input', { type: 'url', placeholder: 'https://passportkey-sync.you.workers.dev', id: 'url' });
    const invite = h('input', { type: 'text', autocomplete: 'off', id: 'invite' });
    const go = h('button', { class: 'primary block', type: 'submit' }, mode === 'create' ? 'Create vault' : 'Sign in');

    const form = h(
      'form',
      {
        onsubmit: async (ev) => {
          ev.preventDefault();
          err.textContent = '';
          if (mode === 'create' && pw.value !== pw2.value) {
            err.textContent = 'The two passwords do not match.';
            return;
          }
          go.disabled = true;
          go.textContent = 'Working...';
          try {
            await call('ui:setup', {
              mode,
              accountName: acct.value,
              password: pw.value,
              syncUrl: url.value,
              inviteCode: invite.value
            });
            await render();
          } catch (e) {
            err.textContent = e.message;
            go.disabled = false;
            go.textContent = mode === 'create' ? 'Create vault' : 'Sign in';
          }
        }
      },
      field('Account name', acct),
      field('Master password', pw),
      mode === 'create' ? field('Confirm master password', pw2) : null,
      field(mode === 'create' ? 'Sync server URL (optional)' : 'Sync server URL', url),
      h('details', { class: 'small' }, h('summary', null, 'Invite code'), h('div', { style: 'margin-top:8px' }, field('Only if your server requires one', invite))),
      mode === 'create'
        ? h('p', { class: 'notice small' }, 'Your master password cannot be recovered. It encrypts your passkeys on this device, and nobody, including your server, can reset it.')
        : null,
      go,
      err
    );

    wrap.replaceChildren(
      h('div', { class: 'header' }, logo()),
      h(
        'div',
        { class: 'tabs', role: 'tablist' },
        h('button', { role: 'tab', 'aria-selected': String(mode === 'create'), onclick: () => { mode = 'create'; err.textContent = ''; draw(); } }, 'Create vault'),
        h('button', { role: 'tab', 'aria-selected': String(mode === 'signin'), onclick: () => { mode = 'signin'; err.textContent = ''; draw(); } }, 'Sign in')
      ),
      form
    );
    acct.focus();
  }
  draw();
  return wrap;
}

// ---------- locked ----------

async function lockedView(st) {
  const err = h('p', { class: 'error', role: 'alert' });
  const pw = h('input', { type: 'password', autocomplete: 'current-password', id: 'pw' });
  const go = h('button', { class: 'primary block', type: 'submit' }, 'Unlock');
  const form = h(
    'form',
    {
      onsubmit: async (ev) => {
        ev.preventDefault();
        err.textContent = '';
        go.disabled = true;
        try {
          await call('ui:unlock', { password: pw.value });
          await render();
        } catch (e) {
          err.textContent = e.message;
          go.disabled = false;
          pw.select();
        }
      }
    },
    field('Master password', pw),
    go,
    err
  );
  setTimeout(() => pw.focus(), 0);
  return h('div', null, h('div', { class: 'header' }, logo()), h('p', { class: 'muted' }, 'Vault for ', h('strong', null, st.account.name)), form);
}

// ---------- unlocked ----------

async function vaultView(st) {
  const creds = await call('ui:list');
  const err = h('p', { class: 'error', role: 'alert' });

  const hasSync = !!st.account.syncUrl;
  let chip;
  if (!hasSync) chip = h('span', { class: 'chip' }, 'Local only');
  else if (st.syncError) chip = h('span', { class: 'chip warn', title: st.syncError }, 'Sync problem');
  else if (st.dirty) chip = h('span', { class: 'chip warn' }, 'Not synced yet');
  else chip = h('span', { class: 'chip ok' }, 'Synced ' + fmtAgo(st.lastSync));

  const list = h('ul', { class: 'list' });
  function drawList() {
    const q = filter.trim().toLowerCase();
    const shown = creds.filter((c) => !q || c.rpId.includes(q) || (c.userName || '').toLowerCase().includes(q));
    list.replaceChildren(
      ...(shown.length
        ? shown.map(credRow)
        : [h('li', { class: 'muted', style: 'padding:12px 4px' }, creds.length ? 'No matches.' : 'No passkeys yet. Create one on any site that supports passkeys.')])
    );
  }

  function credRow(c) {
    let armed = false;
    const del = h('button', { class: 'link danger', 'aria-label': 'Delete passkey for ' + c.rpId }, 'Delete');
    del.addEventListener('click', async () => {
      if (!armed) {
        armed = true;
        del.textContent = 'Sure?';
        setTimeout(() => { armed = false; del.textContent = 'Delete'; }, 3000);
        return;
      }
      try {
        await call('ui:delete', { id: c.id });
        await render();
      } catch (e) {
        err.textContent = e.message;
      }
    });
    return h(
      'li',
      { class: 'item' },
      h('div', null, h('div', { class: 'title' }, c.rpId), h('div', { class: 'sub' }, (c.userName || c.userDisplayName || 'Unnamed account') + ' - added ' + fmtDate(c.createdAt))),
      del
    );
  }

  const search = h('input', {
    type: 'search',
    placeholder: 'Search ' + creds.length + ' passkey' + (creds.length === 1 ? '' : 's'),
    value: filter,
    'aria-label': 'Search passkeys',
    oninput: (e) => { filter = e.target.value; drawList(); }
  });
  drawList();

  const syncBtn = h('button', {
    onclick: async (ev) => {
      ev.target.disabled = true;
      ev.target.textContent = 'Syncing...';
      try { await call('ui:sync'); } catch (e) { /* shown via status chip */ }
      await render();
    }
  }, 'Sync now');

  const lockBtn = h('button', { onclick: async () => { await call('ui:lock'); await render(); } }, 'Lock');

  return h(
    'div',
    null,
    h('div', { class: 'header' }, logo(), chip),
    search,
    list,
    h('div', { class: 'row', style: 'margin-top:12px' }, hasSync ? syncBtn : null, lockBtn),
    err,
    settingsView(st)
  );
}

function settingsView(st) {
  const err = h('p', { class: 'error', role: 'alert' });
  const msg = h('p', { class: 'small muted' });

  const lockMin = h('input', { type: 'number', min: '0', max: '1440', value: String(st.settings.autoLockMinutes), id: 'lockmin' });
  const intercept = h('input', { type: 'checkbox', id: 'intercept' });
  intercept.checked = st.settings.interceptCreate;

  const save = h('button', {
    onclick: async () => {
      err.textContent = '';
      try {
        await call('ui:settings', { settings: { autoLockMinutes: lockMin.value, interceptCreate: intercept.checked } });
        msg.textContent = 'Saved.';
      } catch (e) { err.textContent = e.message; }
    }
  }, 'Save settings');

  const exportBtn = h('button', {
    onclick: async () => {
      try {
        const blob = await call('ui:export');
        const url = URL.createObjectURL(new Blob([JSON.stringify(blob)], { type: 'application/json' }));
        const a = h('a', { href: url, download: 'passportkey-backup-' + new Date().toISOString().slice(0, 10) + '.json' });
        document.body.append(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        msg.textContent = 'Encrypted backup downloaded. It needs your master password to open.';
      } catch (e) { err.textContent = e.message; }
    }
  }, 'Export encrypted backup');

  const fileInput = h('input', {
    type: 'file',
    accept: 'application/json',
    class: 'sr-only',
    id: 'importfile',
    onchange: async (ev) => {
      err.textContent = '';
      const f = ev.target.files[0];
      if (!f) return;
      try {
        const res = await call('ui:import', { blob: JSON.parse(await f.text()) });
        msg.textContent = 'Imported. The vault now holds ' + res.count + ' passkey(s).';
        await render();
      } catch (e) { err.textContent = e.message; }
    }
  });
  const importBtn = h('button', { onclick: () => fileInput.click() }, 'Import backup');

  let armed = false;
  const eraseBtn = h('button', { class: 'danger' }, 'Remove from this device');
  eraseBtn.addEventListener('click', async () => {
    if (!armed) {
      armed = true;
      eraseBtn.textContent = 'Click again to confirm';
      setTimeout(() => { armed = false; eraseBtn.textContent = 'Remove from this device'; }, 4000);
      return;
    }
    try {
      await call('ui:erase', { deleteRemoteCopy: false });
      await render();
    } catch (e) { err.textContent = e.message; }
  });

  return h(
    'details',
    null,
    h('summary', null, 'Settings'),
    h('div', { class: 'stack', style: 'margin-top:10px' },
      field('Auto-lock after (minutes, 0 = never)', lockMin),
      h('label', { class: 'row small' }, intercept, h('span', null, 'Offer to save new passkeys in PassportKey')),
      save,
      h('div', { class: 'row wrap' }, exportBtn, importBtn, fileInput),
      h('p', { class: 'small muted' }, 'Signed in as ' + st.account.name + (st.account.syncUrl ? ' on ' + st.account.syncUrl : ' (local only)')),
      eraseBtn,
      msg,
      err
    )
  );
}

render();
