import { describe, expect, it } from 'vitest';
import { isValidTraceSleuthVersion } from '../../version-validation';

describe('authoritative TraceSleuth version validation', () => {
  it.each([
    '0.2.0', '1.0.0', '0.9.0-rc.1', '1.0.0-rc.1',
    '1.0.0-alpha.1+build.7', '1.0.0+001', '1.0.0--',
    '1.0.0-0', '1.0.0-rc--.A-b+build-5.sha'
  ])('accepts documented SemVer value %s', (value) => {
    expect(isValidTraceSleuthVersion(value)).toBe(true);
  });

  it.each([
    '01.0.0', '1.00.0', '1.0.0-rc.01', '1.0.0-', '1.0',
    '1.0.0-rc..1', ' v1.0.0', '1.0.0+',
    '1.0.0+build..1', '1.0.0-rc+build+extra',
    '1.0.0-rc_1', '1.0.0-01', '1.0.0-rc.00'
  ])('rejects invalid authoritative version %s', (value) => {
    expect(isValidTraceSleuthVersion(value)).toBe(false);
  });

  it('rejects excessive repeated prerelease identifiers', () => {
    const adversarialVersion = '0.0.0-0.' + '--.'.repeat(100) + '!';
    expect(isValidTraceSleuthVersion(adversarialVersion)).toBe(false);
  });
});
