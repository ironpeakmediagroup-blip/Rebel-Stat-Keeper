// Cloudflare Worker (with static assets) — root entry point.
//
// 2026-09-04: this project started as a classic Cloudflare Pages
// "Connect to Git" deploy, but Cloudflare's current dashboard provisions
// new Git-connected projects as a plain Worker (deploy command
// `npx wrangler deploy`) instead — that runtime auto-serves a `dist`/
// `public`/`build` folder if it recognizes one, but doesn't auto-detect
// plain HTML sitting at the repo root, hence the
// "Could not detect a directory containing static files" error. Fix:
// this file + wrangler.jsonc's "assets" block take over that job
// explicitly — env.ASSETS.fetch(request) serves the HTML files exactly
// like a static host would, and this file's fetch handler intercepts only
// the one real API route (/api/publish-stat) before falling through to
// that static-asset serving.
//
// This POST route is the piece that lets stat_keeper.html be a real
// hosted website instead of relying on the iPad's browser connecting
// straight to obs-websocket over local WiFi (the setup that kept needing
// a re-scan/resync before every game). stat_keeper.html POSTs its state
// here on every change; this handler holds the Pusher app secret (never
// exposed to the browser) and triggers a Pusher event server-side. The 5
// OBS graphic files subscribe to that Pusher channel directly over the
// internet, so there's no LAN dependency left on either end.
//
// Required environment variables/secrets (set in the dashboard —
// Settings > Variables and secrets — NOT committed to this file):
//   PUSHER_APP_ID
//   PUSHER_KEY       (same public value hard-coded into the 5 graphic files)
//   PUSHER_SECRET    (server-side only — never put this in an HTML file)
//   PUSHER_CLUSTER   (same public value hard-coded into the 5 graphic files)
//
// Pusher's REST "trigger event" endpoint requires the request to be signed
// with HMAC-SHA256 over a string that includes an MD5 hash of the request
// body. Cloudflare's WebCrypto supports HMAC-SHA256 natively but does NOT
// implement MD5, so md5Hex() below is a small hand-rolled implementation
// of the (public, unencumbered) RFC 1321 algorithm — verified against
// Python's hashlib on known test vectors before shipping.

const PUSHER_EVENT_NAME = 'state-update';
const MAX_EVENT_BODY_BYTES = 9000; // Pusher's per-event payload cap is 10KB

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/api/publish-stat') {
      if (request.method === 'POST') return handlePublishStatPost(request, env);
      if (request.method === 'GET') return json({ ok: true, note: 'POST state here to publish it to OBS.' }, 200);
      return json({ error: 'method not allowed' }, 405);
    }

    // Everything else is a static file (stat_keeper.html, the 5 OBS
    // graphic files, etc.) — hand off to the assets binding.
    return env.ASSETS.fetch(request);
  }
};

async function handlePublishStatPost(request, env) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ error: 'invalid JSON body' }, 400);
  }

  const { channel, state } = body || {};
  if (!channel || typeof channel !== 'string' || !state) {
    return json({ error: 'missing "channel" or "state"' }, 400);
  }

  const { PUSHER_APP_ID, PUSHER_KEY, PUSHER_SECRET, PUSHER_CLUSTER } = env;
  if (!PUSHER_APP_ID || !PUSHER_KEY || !PUSHER_SECRET || !PUSHER_CLUSTER) {
    return json({ error: 'server missing Pusher configuration' }, 500);
  }

  const eventBody = JSON.stringify({
    name: PUSHER_EVENT_NAME,
    channel,
    data: JSON.stringify({ state })
  });

  if (eventBody.length > MAX_EVENT_BODY_BYTES) {
    return json({ error: 'state payload too large for a single Pusher event' }, 413);
  }

  try {
    const pusherRes = await triggerPusherEvent({
      appId: PUSHER_APP_ID,
      key: PUSHER_KEY,
      secret: PUSHER_SECRET,
      cluster: PUSHER_CLUSTER,
      body: eventBody
    });

    if (!pusherRes.ok) {
      const detail = await pusherRes.text().catch(() => '');
      return json({ error: 'Pusher rejected the event', status: pusherRes.status, detail }, 502);
    }
  } catch (e) {
    return json({ error: 'failed to reach Pusher', detail: String(e) }, 502);
  }

  return json({ ok: true }, 200);
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

async function triggerPusherEvent({ appId, key, secret, cluster, body }) {
  const path = `/apps/${appId}/events`;
  const timestamp = Math.floor(Date.now() / 1000);
  const bodyMd5 = md5Hex(body);

  const params = {
    auth_key: key,
    auth_timestamp: String(timestamp),
    auth_version: '1.0',
    body_md5: bodyMd5
  };
  const queryString = Object.keys(params)
    .sort()
    .map(k => `${k}=${params[k]}`)
    .join('&');

  const stringToSign = `POST\n${path}\n${queryString}`;
  const signature = await hmacSha256Hex(secret, stringToSign);

  const url = `https://api-${cluster}.pusher.com${path}?${queryString}&auth_signature=${signature}`;

  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body
  });
}

// ── crypto helpers ────────────────────────────────────────────────────

async function hmacSha256Hex(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return bufToHex(sig);
}

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/* Pure-JS MD5 (RFC 1321). Only needed because Pusher's REST auth scheme
   requires an MD5 hash of the request body and Workers' WebCrypto
   supports SHA-1/256/384/512 but not MD5. Verified against Python's
   hashlib on "", "abc", a 43-char pangram, and 55/56/64-byte inputs
   (block-boundary cases) before shipping — all matched exactly. */
function md5Hex(input) {
  const s = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ];
  const K = new Int32Array(64);
  for (let i = 0; i < 64; i++) {
    K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296);
  }

  const bytes = new TextEncoder().encode(input);
  const origLenBits = bytes.length * 8;

  const totalLen = ((bytes.length + 8) >> 6) * 64 + 64;
  const withPad = new Uint8Array(totalLen);
  withPad.set(bytes);
  withPad[bytes.length] = 0x80;
  const dv = new DataView(withPad.buffer);
  dv.setUint32(totalLen - 8, origLenBits >>> 0, true);
  dv.setUint32(totalLen - 4, Math.floor(origLenBits / 4294967296), true);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

  for (let chunkStart = 0; chunkStart < totalLen; chunkStart += 64) {
    const M = new Int32Array(16);
    for (let j = 0; j < 16; j++) M[j] = dv.getUint32(chunkStart + j * 4, true);

    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + M[g]) | 0;
      A = D; D = C; C = B;
      B = (B + rotl(F, s[i])) | 0;
    }
    a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
  }

  return toHexLE(a0) + toHexLE(b0) + toHexLE(c0) + toHexLE(d0);
}

function rotl(x, c) {
  return (x << c) | (x >>> (32 - c));
}

function toHexLE(n) {
  const buf = new ArrayBuffer(4);
  new DataView(buf).setInt32(0, n, true);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
