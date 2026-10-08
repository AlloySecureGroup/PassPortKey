# PassportKey

Portable passkeys for Chrome. The extension acts as a virtual WebAuthn authenticator, keeps your passkeys in an end-to-end encrypted vault, and syncs that vault through a tiny Cloudflare Worker that you own. The server only ever stores ciphertext.

```
 Web page            Chrome extension (MV3)                      Your Cloudflare account
+---------+   inject.js wraps navigator.credentials    +-------------------------------+
| site.com| -> content.js relays -> background.js  --> | Worker + D1: one encrypted    |
+---------+   approval window (you click Approve)      | blob per vault, version-checked|
                vault: AES-256-GCM, key from PBKDF2     +-------------------------------+
```

## Quick start

### 1. Deploy the sync server (about 3 minutes)

```bash
cd worker
npx wrangler login
npx wrangler d1 create passportkey          # copy the database_id it prints into wrangler.toml
npx wrangler d1 execute passportkey --remote --file=schema.sql
npx wrangler secret put INVITE_CODE         # optional: stops strangers creating vaults on your server
npx wrangler deploy                         # prints https://passportkey-sync.<you>.workers.dev
```

Skipping this step is fine: choose "Create vault" without a sync URL and PassportKey works as a local-only vault. You can export an encrypted backup from Settings.

### 2. Load the extension

1. Open `chrome://extensions` and turn on Developer mode.
2. Click Load unpacked and select the `extension` folder.
3. Pin PassportKey, open it, and choose Create vault. Enter an account name, a master password (10+ characters), and your Worker URL.

### 3. Use it

- Register: on any site, choose "Create passkey". A PassportKey window opens showing the real site name. Click Save passkey.
- Sign in: click the site's passkey sign-in button. Pick the account and click Continue.
- On a new browser or computer: install the extension, choose Sign in, and enter the same account name, master password and Worker URL. Your passkeys appear.

"Use another method" in the window hands the request to Chrome's built-in passkey UI, so you are never locked out of a site.

## How it works

| Piece | File | Job |
| --- | --- | --- |
| Page hook | `extension/inject.js` | Runs in the page's MAIN world. Wraps `navigator.credentials.create/get`, returns real `PublicKeyCredential` objects, falls through to Chrome when PassportKey cannot serve a request. |
| Relay | `extension/content.js` | Passes messages between the page and the service worker. No secrets. |
| Service worker | `extension/background.js` | Validates origin and rpId, opens the approval window, signs. The only code that touches private keys. |
| Authenticator | `extension/lib/webauthn.js` | ES256 key generation, `none` attestation, authenticatorData, DER signatures. Sets backup flags (BE and BS) so sites treat these as synced passkeys. |
| Vault | `extension/lib/vault.js`, `store.js` | Key derivation, AES-GCM encryption, lock state, merge logic, sync loop. |
| Sync server | `worker/src/index.js` | Compare-and-swap storage of one blob per vault. |

### Security model

- **Key derivation.** PBKDF2-SHA256, 600,000 iterations, 64 bytes out. The first 32 bytes are the AES-256-GCM vault key and never leave your device. The last 32 bytes are the sync credential; the server stores only its SHA-256, and the vault id is a different hash of it.
- **Salt** is derived from your account name, so a new device can find and authenticate to your vault before it has downloaded anything.
- **Phishing resistance.** The origin and rpId are computed in the service worker from the real page URL, never taken from page-supplied data. The rpId must equal the page host or be a parent domain, over https (or localhost). The window shows the site name from that check.
- **Verification flag.** UV is only set when you typed your master password for that operation. If a site requires user verification, the window asks for the password again.
- **Unlocked state** lives in `chrome.storage.session` (memory only, cleared when Chrome closes, not readable by content scripts) and auto-locks after 15 minutes by default.
- **Local hint index.** So that a locked vault does not hijack every sign-in, a local-only list of SHA-256 hashes of the sites you have passkeys for is kept unencrypted. It is not synced.
- **Sync conflicts.** Each credential has an `updatedAt`; newest wins per credential, and deletions are kept as 90-day tombstones so stale devices cannot resurrect them. The server rejects writes based on an old version, and the client re-merges and retries.

## Testing

```bash
npm install
npm test            # 13 unit tests, ~11 seconds
npm run test:e2e    # real Chromium with the extension loaded, ~1 minute
```

- The unit tests check registrations and sign-ins with `@simplewebauthn/server`, an independent relying-party library, and run two simulated devices through the real Worker code against an in-memory stand-in for D1.
- The end-to-end test launches Chromium with the extension, runs a local relying party, registers and signs in, then starts a second, empty Chrome profile that signs in from the sync server and logs in with the same passkey. It also covers user verification, locked vault, cancel, and the rpId security check.

## Known limitations (v0.1)

- **No autofill-style passkey prompts.** Conditional mediation requests fall through to Chrome. Sites that offer a "Sign in with passkey" button work; the passkey suggestion inside the username field does not.
- **Top-level frames only.** Passkeys inside cross-origin iframes are not intercepted.
- **ES256 only, no attestation.** Sites that demand hardware-backed or enterprise attestation will not accept these passkeys.
- **No master password change yet.** The vault id derives from the password, so changing it means starting a new vault. Treat the password as permanent for now.
- **No recovery.** Lose the master password and the vault is unreadable by design. Keep an exported backup and the password somewhere safe.
- **PBKDF2 instead of Argon2id,** because WebCrypto does not provide Argon2. The iteration count is high but memory-hard hashing would be stronger.
- **Approximate Public Suffix List.** A short built-in deny list stops rpIds like `co.uk` or `github.io`. A full PSL would be stricter.
- **A malicious sync server** cannot read your vault, but it could delete it or serve you an older version. Keep backups.
- **Not yet tried against real services.** Tested against a standards-compliant relying party and a fake D1, not a live Cloudflare deployment or big sites such as Google or GitHub. Expect to find site-specific quirks.
- A browser extension is a high-value target. Review the code before trusting it with real accounts, and start with low-stakes sites.

## Project layout

```
extension/   Chrome MV3 extension (load this folder)
worker/      Cloudflare Worker, D1 schema, wrangler config
test/        unit tests and end-to-end browser test
```
