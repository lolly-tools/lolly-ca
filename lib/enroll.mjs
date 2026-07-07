// SPDX-License-Identifier: MPL-2.0
/**
 * Enrollment: verify the HMAC token + proof-of-possession, then issue a
 * short-lived leaf via engine/src/x509.js. CSR-less — the client sends its
 * raw SPKI plus an ECDSA P-256/SHA-256 signature (raw 64-byte r||s) over the
 * exact enrollment-token string. Same soundness as a PKCS#10 CSR without an
 * ASN.1 CSR parser server-side.
 */

import { issueLeafCert, pemToDer, derToPem } from '../../../engine/src/x509.ts';
import { b64uToBytes, verifyEnrollToken } from './tokens.mjs';

const te = new TextEncoder();
const subtle = globalThis.crypto.subtle;

const DAY_MS = 24 * 3600 * 1000;
const ALLOWED_DAYS = [7, 30, 90, 365]; // the user-selectable lifetimes

/**
 * Proof-of-possession: the presented SPKI's private key must have signed the
 * exact token string. → { ok: true, spkiDer } | { ok: false, error }
 */
export async function verifyPop({ token, spki, pop }) {
  const spkiDer = b64uToBytes(spki);
  const sig = b64uToBytes(pop);
  if (sig.length !== 64) return { ok: false, error: 'pop must be a raw 64-byte ECDSA P-256 signature' };
  let key;
  try {
    key = await subtle.importKey('spki', spkiDer, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  } catch {
    return { ok: false, error: 'spki is not a P-256 public key' };
  }
  const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, te.encode(String(token)));
  return ok ? { ok: true, spkiDer } : { ok: false, error: 'proof-of-possession signature does not verify' };
}

// Requested lifetime must be one of ALLOWED_DAYS; anything else falls back to
// CA_CERT_DAYS (default 30), and everything is capped at CA_CERT_MAX_DAYS.
function leafDays(env, requested) {
  const fallback = Number(env.CA_CERT_DAYS) || 30;
  const max = Number(env.CA_CERT_MAX_DAYS) || 365;
  const days = ALLOWED_DAYS.includes(Number(requested)) ? Number(requested) : fallback;
  return Math.min(days, max);
}

// Issuance log: one JSON line to stdout (→ Vercel function logs) plus an
// optional fire-and-forget webhook POST — issuance never blocks on it.
async function logIssuance(env, { email, provider, certDer, notAfter }) {
  const digest = new Uint8Array(await subtle.digest('SHA-256', certDer));
  const serialHint = Array.from(digest.subarray(0, 4), (b) => b.toString(16).padStart(2, '0')).join('');
  const entry = { at: new Date().toISOString(), email, provider, serialHint, notAfter: notAfter.toISOString() };
  console.log(JSON.stringify(entry));
  if (env.CA_LOG_WEBHOOK) {
    fetch(env.CA_LOG_WEBHOOK, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(entry),
    }).catch(() => {});
  }
}

/**
 * The full enrollment: token → PoP → leaf. Returns a { status, json } result
 * the handler writes verbatim (and tests call directly, no socket).
 */
export async function enroll({ token, spki, pop, days } = {}, env) {
  if (!token || !spki || !pop) return { status: 400, json: { error: 'token, spki and pop are required' } };
  const t = await verifyEnrollToken(String(token), env.CA_SERVICE_SECRET);
  if (!t.ok) return { status: 401, json: { error: t.error } };
  const p = await verifyPop({ token: String(token), spki, pop });
  if (!p.ok) return { status: 401, json: { error: p.error } };
  if (!env.CA_ROOT_CERT_PEM || !env.CA_ROOT_KEY_PEM) return { status: 500, json: { error: 'CA root is not configured' } };

  const caCertDer = pemToDer(env.CA_ROOT_CERT_PEM);
  // derTime writes whole seconds — truncate so the reported ISO strings match
  // the certificate exactly.
  const notBefore = new Date(Math.floor((Date.now() - 60_000) / 1000) * 1000);
  // Token-embedded days (magic-link flow, server-minted) win over the POST
  // body's (popup flow, same session) — both pass through the leafDays clamp.
  const notAfter = new Date(notBefore.getTime() + leafDays(env, t.payload.days ?? days) * DAY_MS);
  const certDer = await issueLeafCert({
    caCertDer,
    caPrivateKey: pemToDer(env.CA_ROOT_KEY_PEM),
    spkiDer: p.spkiDer,
    email: t.payload.email,
    notBefore,
    notAfter,
  });

  await logIssuance(env, { email: t.payload.email, provider: t.payload.provider, certDer, notAfter });

  const certPem = derToPem(certDer, 'CERTIFICATE');
  return {
    status: 200,
    json: {
      cert: certPem,
      chain: [certPem, derToPem(caCertDer, 'CERTIFICATE')], // leaf-first, root normalised
      identity: { email: t.payload.email, provider: t.payload.provider },
      notBefore: notBefore.toISOString(),
      notAfter: notAfter.toISOString(),
    },
  };
}
