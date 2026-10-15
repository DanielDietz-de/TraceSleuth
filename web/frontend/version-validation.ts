// Parse SemVer with bounded, unambiguous components. A single nested regex
// over untrusted input can cause catastrophic backtracking (CodeQL js/redos).
// The authoritative VERSION is a short build-time value, not user-supplied data.
const coreNumber = /^(0|[1-9][0-9]*)$/;
const asciiIdentifier = /^[0-9A-Za-z-]+$/;
const digitsOnly = /^[0-9]+$/;

function validIdentifiers(value: string, prerelease: boolean): boolean {
  if (!value) return false;
  return value.split('.').every((identifier) =>
    asciiIdentifier.test(identifier) &&
    (!prerelease || !digitsOnly.test(identifier) || coreNumber.test(identifier))
  );
}

export function isValidTraceSleuthVersion(value: string): boolean {
  // Protect build-time processing and refuse whitespace/control characters.
  if (!value || value.length > 256) return false;

  const plus = value.indexOf('+');
  if (plus !== -1) {
    if (value.indexOf('+', plus + 1) !== -1 ||
        !validIdentifiers(value.slice(plus + 1), false)) {
      return false;
    }
    value = value.slice(0, plus);
  }

  const hyphen = value.indexOf('-');
  if (hyphen !== -1) {
    if (!validIdentifiers(value.slice(hyphen + 1), true)) return false;
    value = value.slice(0, hyphen);
  }

  const parts = value.split('.');
  return parts.length === 3 && parts.every((part) => coreNumber.test(part));
}
