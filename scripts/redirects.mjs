// The finish URI the demo registers, and the one it sends, are the same address.
// A loopback URI follows the port the demo listens on. Any other host is left as written.

const LOOPBACK = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

function portNumber(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return undefined;
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return undefined;
  return port;
}

/** Replace the port of a loopback URL. Anything else, including an unparseable value, is returned unchanged. */
export function onPort(url, port) {
  try {
    const next = new URL(url);
    if (!LOOPBACK.has(next.hostname)) return url;
    next.port = String(port);
    return next.href;
  } catch {
    return url;
  }
}

/**
 * The finish and display URIs to register.
 * An explicit public URL replaces the origin and keeps the path.
 * Otherwise `port` moves a loopback URI onto the port the demo listens on.
 */
export function redirectsFor(finishUri, displayUri, options) {
  const listed = (finish, display) => ({
    finishUri: finish,
    ...(display ? { displayUri: display } : {}),
  });
  if (options.publicUrlGiven && options.publicUrl) {
    const base = new URL(options.publicUrl.endsWith('/') ? options.publicUrl : `${options.publicUrl}/`);
    const move = (value) => {
      if (!value) return value;
      const next = new URL(value);
      next.protocol = base.protocol;
      next.hostname = base.hostname;
      next.port = base.port;
      return next.href;
    };
    return listed(move(finishUri), move(displayUri));
  }
  if (options.port) {
    return listed(onPort(finishUri, options.port), displayUri ? onPort(displayUri, options.port) : displayUri);
  }
  return listed(finishUri, displayUri);
}

/** The container's PORT wins when it is a port. Otherwise the environment. An empty or unusable value is absent. */
export function demoPort(envPort, containerPort) {
  return portNumber(containerPort) ?? portNumber(envPort);
}
