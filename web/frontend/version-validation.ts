// The browser build must accept the SemVer release candidates permitted by
// docs/project/VERSIONING.md, not only final MAJOR.MINOR.PATCH tags.
// Numeric identifiers cannot start with zero; alphanumeric prerelease and
// build identifiers use SemVer's ASCII grammar.
const semver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export function isValidTraceSleuthVersion(value: string): boolean {
  return semver.test(value);
}
