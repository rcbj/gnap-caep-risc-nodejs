/**
 * What kind of failure a {@link GnapError} is. An application usually answers every one of them the
 * same way (the sign-in failed, start again), and logs the code and message for the operator.
 *
 * - `config`: the configuration is incomplete or contradictory.
 * - `discovery`: the grant server, the OpenID issuer, or the transmitter could not be read.
 * - `protocol`: the authorization server answered a GNAP error, or not with the document this client asked for.
 * - `validation`: a check on a callback, a token, or a subject failed (hash, audience, time, origin).
 * - `signature`: a key proof or a token's signature does not verify, or uses an algorithm this client refuses.
 * - `ssf`: the Shared Signals transmitter could not be found, or its stream created or polled.
 */
export type GnapErrorCode = 'config' | 'discovery' | 'protocol' | 'validation' | 'signature' | 'ssf';

/** A continuation the authorization server returned with an error, usually `too_fast`. */
export interface ErrorContinuation {
  uri: string;
  accessToken: string;
  wait?: number;
}

/** Every failure this module reports is one of these. */
export class GnapError extends Error {
  /** What kind of failure it is. */
  readonly code: GnapErrorCode;
  /** The GNAP `error` code, when the authorization server named one (`user_denied`, `too_fast`, ...). */
  readonly gnapError?: string;
  /** The `context` the grant request was started with, when a finish fails after the browser returns. */
  context?: unknown;
  /** A replacement `continue` from the error body. */
  readonly continuation?: ErrorContinuation;

  constructor(code: GnapErrorCode, message: string, options: {
    cause?: unknown;
    gnapError?: string;
    context?: unknown;
    continuation?: ErrorContinuation;
  } = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'GnapError';
    this.code = code;
    if (options.gnapError) this.gnapError = options.gnapError;
    if (options.context !== undefined) this.context = options.context;
    if (options.continuation) this.continuation = options.continuation;
  }
}
