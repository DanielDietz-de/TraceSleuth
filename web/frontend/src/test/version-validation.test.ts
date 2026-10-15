import { describe, expect, it } from 'vitest';
import { isValidTraceSleuthVersion } from '../../version-validation';

describe('authoritative TraceSleuth version validation', () => {
  it.each(['0.2.0', '1.0.0', '0.9.0-rc.1', '1.0.0-rc.1', '1.0.0-alpha.1+build.7'])(
    'accepts documented SemVer value %s', (value) => {
      expect(isValidTraceSleuthVersion(value)).toBe(true);
    }
  );

  it.each(['01.0.0', '1.00.0', '1.0.0-rc.01', '1.0.0-', '1.0', '1.0.0-rc..1', ' v1.0.0'])(
    'rejects invalid authoritative version %s', (value) => {
      expect(isValidTraceSleuthVersion(value)).toBe(false);
    }
  );
});
