// Small string helpers that run in linear time. A regular expression such as /\/+$/ is quadratic on a
// long run of slashes that is not at the end (V8 retries the run from every position), and the
// strings here come from configuration and from what a server answers.

/** `value` without its trailing slashes. */
export function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 0x2f) end -= 1;
  return end === value.length ? value : value.slice(0, end);
}
