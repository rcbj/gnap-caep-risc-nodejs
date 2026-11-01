// Grant-server discovery is an OPTIONS on the grant endpoint (RFC 9635 section 9). The ID token's
// issuer is an OpenID Provider, discovered the usual way, and only so its JWKS can check the subject
// assertion. The Shared Signals transmitter is discovered by inserting `/.well-known/ssf-configuration`
// and, if that is not there, appending it.

import { GnapError } from './errors.ts';
import { send, type TlsOptions } from './http.ts';

/** What this client reads from a grant server's OPTIONS document. Other members are ignored. */
export interface GrantServerMetadata {
  grant_request_endpoint: string;
  interaction_start_modes_supported?: string[];
  interaction_finish_methods_supported?: string[];
  key_proofs_supported?: string[];
  sub_id_formats_supported?: string[];
  assertion_formats_supported?: string[];
}

/** `inserted` first, then `appended`, and only one of them when they are the same URL. */
export function wellKnownUrls(issuer: string, suffix: string): string[] {
  const url = new URL(issuer);
  const path = url.pathname.replace(/\/+$/, '');
  const inserted = `${url.origin}/.well-known/${suffix}${path}`;
  const appended = `${url.origin}${path}/.well-known/${suffix}`;
  return inserted === appended ? [inserted] : [inserted, appended];
}

function listOf(value: unknown): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new GnapError('discovery', 'a grant-server metadata list is not an array of strings');
  }
  return value;
}

/** Checks an OPTIONS document and that `grant_request_endpoint` is the endpoint that was asked (mix-up). */
export function validateGrantServer(raw: unknown, grantEndpoint: string): GrantServerMetadata {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new GnapError('discovery', 'grant-server metadata must be a JSON object');
  const doc = raw as Record<string, unknown>;
  if (typeof doc.grant_request_endpoint !== 'string' || !doc.grant_request_endpoint) {
    throw new GnapError('discovery', 'grant-server metadata has no grant_request_endpoint');
  }
  const advertised = new URL(doc.grant_request_endpoint).href.replace(/\/+$/, '');
  const asked = new URL(grantEndpoint).href.replace(/\/+$/, '');
  if (advertised !== asked) {
    throw new GnapError('discovery', `the grant server says its endpoint is ${doc.grant_request_endpoint}, not ${grantEndpoint}`);
  }
  return {
    grant_request_endpoint: doc.grant_request_endpoint,
    interaction_start_modes_supported: listOf(doc.interaction_start_modes_supported),
    interaction_finish_methods_supported: listOf(doc.interaction_finish_methods_supported),
    key_proofs_supported: listOf(doc.key_proofs_supported),
    sub_id_formats_supported: listOf(doc.sub_id_formats_supported),
    assertion_formats_supported: listOf(doc.assertion_formats_supported),
  };
}

/** OPTIONS on the grant endpoint. */
export async function discoverGrantServer(grantEndpoint: string, tls: TlsOptions): Promise<GrantServerMetadata> {
  const answer = await send(grantEndpoint, { method: 'OPTIONS', headers: { accept: 'application/json' } }, tls, 'discovery');
  let json: unknown;
  try {
    json = JSON.parse(answer.body);
  } catch (err) {
    throw new GnapError('discovery', `${grantEndpoint} did not answer JSON grant-server metadata (${answer.status})`, { cause: err });
  }
  if (answer.status !== 200) throw new GnapError('discovery', `${grantEndpoint} answered ${answer.status} for discovery`);
  return validateGrantServer(json, grantEndpoint);
}

export interface OpenIdMetadata {
  issuer: string;
  jwks_uri: string;
}

/** The OpenID Provider metadata of `issuer`, so the subject ID token can be checked. */
export async function discoverOpenId(issuer: string, tls: TlsOptions): Promise<OpenIdMetadata> {
  const urls = wellKnownUrls(issuer, 'openid-configuration');
  let last = new GnapError('discovery', `no OpenID Provider metadata at ${urls.join(' or ')}`);
  for (const url of urls) {
    const answer = await send(url, { headers: { accept: 'application/json' } }, tls, 'discovery');
    if (answer.status === 404 && url !== urls[urls.length - 1]) continue;
    let doc: { issuer?: string; jwks_uri?: string } | undefined;
    try {
      doc = JSON.parse(answer.body) as { issuer?: string; jwks_uri?: string };
    } catch {
      doc = undefined;
    }
    if (answer.status !== 200 || !doc?.jwks_uri) {
      last = new GnapError('discovery', `${url} answered ${answer.status} without OpenID Provider metadata`);
      continue;
    }
    if (doc.issuer && doc.issuer.replace(/\/+$/, '') !== issuer.replace(/\/+$/, '')) {
      throw new GnapError('discovery', `${url} says its issuer is ${doc.issuer}, not ${issuer}`);
    }
    return { issuer: doc.issuer ?? issuer, jwks_uri: doc.jwks_uri };
  }
  throw last;
}
