/**
 * gnap-caep-risc-nodejs: a server-side GNAP client for a traditional web application.
 *
 * ```ts
 * import { GnapClient } from 'gnap-caep-risc-nodejs';
 *
 * const gnap = GnapClient.fromFile('gnap.json');   // loads the key; does not discover
 * const started = await gnap.requestGrant();       // send the browser to started.redirectUrl
 * const done = await gnap.finishRedirect(query, { allowedIds });
 * ```
 *
 * The private key stays in this process. Tokens are key-bound. The browser carries only the
 * interaction hash.
 *
 * @packageDocumentation
 */

export { GnapClient } from './client.ts';
export type { Continuation, FinishedGrant, Grant, GrantRequestOptions, PendingGrant, SecurityPosture } from './client.ts';
export { readConfigFile, resolveConfig } from './config.ts';
export type { GnapConfigFile, ResolvedConfig } from './config.ts';
export { discoverGrantServer, discoverOpenId, validateGrantServer, wellKnownUrls } from './discovery.ts';
export type { GrantServerMetadata, OpenIdMetadata } from './discovery.ts';
export { GnapError } from './errors.ts';
export type { GnapErrorCode } from './errors.ts';
export { interactionHash } from './hash.ts';
export { loadClientKey, publicKeyObject } from './keys.ts';
export { fetchTlsChain } from './trust.ts';
export type { TlsChain } from './trust.ts';
export type { ClientKey, KeyProof, PublicJwk } from './keys.ts';
export { personFrom } from './subject.ts';
export type { Person } from './subject.ts';
export { createSelfSignedKeyPair } from './x509.ts';
export { SignalsReceiver } from './ssf/receiver.ts';
export type { SignalEvent, SignalsReceiverOptions, SignedRequest } from './ssf/receiver.ts';
export { MemorySessionIndex, trackedFromPerson } from './ssf/session-index.ts';
export type { SessionIndex, TrackedSession } from './ssf/session-index.ts';
export { EVENT, CAEP_EVENTS, RISC_EVENTS, DEFAULT_EVENTS_REQUESTED, DEFAULT_ENDING_EVENTS, subjectOf } from './ssf/events.ts';
export type { SubjectRef } from './ssf/events.ts';
