// Runs in the page's MAIN world at document_start.
// Wraps navigator.credentials.create() and .get(). If PassportKey can serve the request it
// answers with a PublicKeyCredential-shaped object; otherwise it falls through to Chrome's
// native implementation. No secrets ever pass through this file: only public WebAuthn data.

(() => {
  if (window.__passportkeyInstalled) return;
  Object.defineProperty(window, '__passportkeyInstalled', { value: true });

  if (!window.PublicKeyCredential || !window.CredentialsContainer) return;

  const proto = CredentialsContainer.prototype;
  const nativeCreate = proto.create;
  const nativeGet = proto.get;

  // ---- encoding helpers ----
  const toBytes = (src) =>
    src instanceof ArrayBuffer
      ? new Uint8Array(src)
      : new Uint8Array(src.buffer, src.byteOffset, src.byteLength);

  function b64uEncode(src) {
    const bytes = toBytes(src);
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64uDecode(str) {
    const pad = '='.repeat((4 - (str.length % 4)) % 4);
    const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  // ---- message bridge to the isolated-world relay (content.js) ----
  let seq = 0;
  const waiting = new Map();

  window.addEventListener('message', (ev) => {
    if (ev.source !== window) return;
    const d = ev.data;
    if (!d || d.channel !== 'passportkey-res' || !waiting.has(d.id)) return;
    const done = waiting.get(d.id);
    waiting.delete(d.id);
    done(d.result);
  });

  function ask(type, payload) {
    return new Promise((resolve) => {
      const id = 'pk' + ++seq + '-' + Math.random().toString(36).slice(2);
      waiting.set(id, resolve);
      window.postMessage({ channel: 'passportkey-req', id, type, payload }, '*');
    });
  }

  // ---- building WebAuthn result objects ----
  function define(obj, props) {
    for (const [k, v] of Object.entries(props)) {
      Object.defineProperty(obj, k, { value: v, enumerable: true, configurable: true, writable: false });
    }
  }

  function buildCreateResult(r, wantsCredProps) {
    const resp = Object.create(AuthenticatorAttestationResponse.prototype);
    const clientDataJSON = b64uDecode(r.clientDataJSON);
    const attestationObject = b64uDecode(r.attestationObject);
    define(resp, {
      clientDataJSON,
      attestationObject,
      getTransports: () => r.transports.slice(),
      getAuthenticatorData: () => b64uDecode(r.authenticatorData),
      getPublicKey: () => b64uDecode(r.publicKey),
      getPublicKeyAlgorithm: () => r.publicKeyAlgorithm
    });
    const ext = wantsCredProps ? { credProps: { rk: true } } : {};
    const cred = Object.create(PublicKeyCredential.prototype);
    define(cred, {
      id: r.id,
      rawId: b64uDecode(r.id),
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: resp,
      getClientExtensionResults: () => Object.assign({}, ext),
      toJSON: () => ({
        id: r.id,
        rawId: r.id,
        type: 'public-key',
        authenticatorAttachment: 'platform',
        response: {
          clientDataJSON: r.clientDataJSON,
          attestationObject: r.attestationObject,
          authenticatorData: r.authenticatorData,
          publicKey: r.publicKey,
          publicKeyAlgorithm: r.publicKeyAlgorithm,
          transports: r.transports.slice()
        },
        clientExtensionResults: Object.assign({}, ext)
      })
    });
    return cred;
  }

  function buildGetResult(r) {
    const resp = Object.create(AuthenticatorAssertionResponse.prototype);
    define(resp, {
      clientDataJSON: b64uDecode(r.clientDataJSON),
      authenticatorData: b64uDecode(r.authenticatorData),
      signature: b64uDecode(r.signature),
      userHandle: r.userHandle ? b64uDecode(r.userHandle) : null
    });
    const cred = Object.create(PublicKeyCredential.prototype);
    define(cred, {
      id: r.id,
      rawId: b64uDecode(r.id),
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: resp,
      getClientExtensionResults: () => ({}),
      toJSON: () => ({
        id: r.id,
        rawId: r.id,
        type: 'public-key',
        authenticatorAttachment: 'platform',
        response: {
          clientDataJSON: r.clientDataJSON,
          authenticatorData: r.authenticatorData,
          signature: r.signature,
          userHandle: r.userHandle || undefined
        },
        clientExtensionResults: {}
      })
    });
    return cred;
  }

  function throwIfAborted(signal) {
    if (signal && signal.aborted) {
      throw signal.reason || new DOMException('The operation was aborted.', 'AbortError');
    }
  }

  const describeList = (list) =>
    (list || []).map((c) => ({ id: b64uEncode(c.id), type: c.type, transports: c.transports }));

  // ---- the wrappers ----
  async function create(options) {
    const pk = options && options.publicKey;
    if (!pk) return nativeCreate.call(this, options);
    throwIfAborted(options.signal);
    let result;
    try {
      result = await ask('wa:create', {
        mediation: options.mediation,
        publicKey: {
          rp: { id: pk.rp && pk.rp.id, name: pk.rp && pk.rp.name },
          user: { id: b64uEncode(pk.user.id), name: pk.user.name, displayName: pk.user.displayName },
          challenge: b64uEncode(pk.challenge),
          pubKeyCredParams: pk.pubKeyCredParams,
          excludeCredentials: describeList(pk.excludeCredentials),
          authenticatorSelection: pk.authenticatorSelection,
          hints: pk.hints,
          attestation: pk.attestation
        }
      });
    } catch {
      result = { handled: false };
    }
    throwIfAborted(options.signal);
    if (!result || !result.handled) return nativeCreate.call(this, options);
    if (result.error) throw new DOMException(result.error.message, result.error.name);
    const wantsCredProps = !!(pk.extensions && pk.extensions.credProps);
    return buildCreateResult(result.response, wantsCredProps);
  }

  async function get(options) {
    const pk = options && options.publicKey;
    if (!pk) return nativeGet.call(this, options);
    throwIfAborted(options.signal);
    let result;
    try {
      result = await ask('wa:get', {
        mediation: options.mediation,
        publicKey: {
          rpId: pk.rpId,
          challenge: b64uEncode(pk.challenge),
          allowCredentials: describeList(pk.allowCredentials),
          userVerification: pk.userVerification,
          hints: pk.hints
        }
      });
    } catch {
      result = { handled: false };
    }
    throwIfAborted(options.signal);
    if (!result || !result.handled) return nativeGet.call(this, options);
    if (result.error) throw new DOMException(result.error.message, result.error.name);
    return buildGetResult(result.response);
  }

  Object.defineProperty(proto, 'create', { value: create, configurable: true, writable: true, enumerable: true });
  Object.defineProperty(proto, 'get', { value: get, configurable: true, writable: true, enumerable: true });
})();
