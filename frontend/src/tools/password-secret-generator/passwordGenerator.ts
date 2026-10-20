import type { PasswordOptions, PasswordPresetId, PassphraseCapitalization, PassphraseSeparator, RecoveryCodeCount, RecoveryCodeFormat, SecretMode, SecretStrength, TokenBits, TokenFormat } from './passwordTypes';
import { exclusionCharacters, matchablePasswordPresets, passphraseSeparatorValues, passphraseWords, passwordCharacters, passwordPresetLabels, passwordPresetMatchKeys, passwordPresets } from './passwordPresets';

export function generatePassword(options: PasswordOptions) {
  const excludeSet = buildPasswordExcludeSet(options);
  const groups = [
    options.lowercase ? filterCharacters(passwordCharacters.lowercase, excludeSet) : '',
    options.uppercase ? filterCharacters(passwordCharacters.uppercase, excludeSet) : '',
    options.numbers ? filterCharacters(passwordCharacters.numbers, excludeSet) : '',
    options.symbols
      ? filterCharacters(options.safeSymbolsOnly ? passwordCharacters.safeSymbols : passwordCharacters.symbols, excludeSet)
      : '',
  ].filter(Boolean);
  const pool = groups.join('');

  if (!pool) {
    throw new Error('Enable at least one character group with usable characters.');
  }

  const requiredCharacters = groups.slice(0, Math.min(groups.length, options.length)).map((group) => randomCharacter(group));
  const remainingCharacters = Array.from({ length: options.length - requiredCharacters.length }, () => randomCharacter(pool));

  return shuffleCharacters([...requiredCharacters, ...remainingCharacters]).join('');
}

export function buildPasswordPool(options: PasswordOptions) {
  const excludeSet = buildPasswordExcludeSet(options);
  const pool = [
    options.lowercase ? passwordCharacters.lowercase : '',
    options.uppercase ? passwordCharacters.uppercase : '',
    options.numbers ? passwordCharacters.numbers : '',
    options.symbols ? (options.safeSymbolsOnly ? passwordCharacters.safeSymbols : passwordCharacters.symbols) : '',
  ].join('');

  return filterCharacters(pool, excludeSet);
}

export function getMatchingPasswordPreset(options: PasswordOptions): PasswordPresetId {
  const matchedPreset = matchablePasswordPresets.find((preset) =>
    passwordPresetMatchKeys.every((key) => options[key] === passwordPresets[preset][key])
  );

  return matchedPreset ?? 'custom';
}

function buildPasswordExcludeSet(options: PasswordOptions) {
  const excludeSet = new Set<string>();
  const keys = [
    'avoidQwertyMismatch',
    'avoidVisualSimilar',
    'avoidQuoteLike',
    'avoidDashUnderscore',
    'avoidSlashBackslashPipe',
    'avoidHardPunctuation',
    'avoidShellSensitive',
    'avoidJsonEnvSensitive',
  ] as const;

  keys.forEach((key) => {
    if (options[key]) {
      for (const character of exclusionCharacters[key]) {
        excludeSet.add(character);
      }
    }
  });

  for (const character of options.customExclude) {
    excludeSet.add(character);
  }

  return excludeSet;
}

export function generatePassphrase(
  wordCount: number,
  separator: PassphraseSeparator,
  capitalization: PassphraseCapitalization,
  addNumber: boolean,
  addSymbol: boolean
) {
  const words = Array.from({ length: wordCount }, () => {
    const word = passphraseWords[secureRandomInt(passphraseWords.length)];

    if (capitalization === 'title') {
      return word[0].toUpperCase() + word.slice(1);
    }

    if (capitalization === 'random') {
      return secureRandomInt(2) === 0 ? word : word[0].toUpperCase() + word.slice(1);
    }

    return word;
  });
  const suffix = [
    addNumber ? String(secureRandomInt(10)) : '',
    addSymbol ? randomCharacter(passwordCharacters.safeSymbols) : '',
  ].join('');

  return `${words.join(passphraseSeparatorValues[separator])}${suffix}`;
}

export function generateToken(bits: TokenBits, format: TokenFormat) {
  if (format === 'uuid') {
    return generateUuidV4();
  }

  const bytes = crypto.getRandomValues(new Uint8Array(bits / 8));

  return format === 'hex' ? bytesToHex(bytes) : bytesToBase64Url(bytes);
}

function generateUuidV4() {
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }

  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytesToHex(bytes);

  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function generatePin(digitCount: number, avoidRepeated: boolean, avoidSequences: boolean, avoidDates: boolean) {
  let fallback = '';

  for (let attempt = 0; attempt < 80; attempt += 1) {
    const candidate = Array.from({ length: digitCount }, () => String(secureRandomInt(10))).join('');
    fallback = candidate;

    if (!isBadPin(candidate, avoidRepeated, avoidSequences, avoidDates)) {
      return candidate;
    }
  }

  return fallback;
}

export function generateRecoveryCodes(count: RecoveryCodeCount, format: RecoveryCodeFormat) {
  const alphabet = format === 'digits' ? passwordCharacters.numbers : 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

  return Array.from({ length: count }, () => {
    const rawCode = Array.from({ length: 8 }, () => randomCharacter(alphabet)).join('');

    return `${rawCode.slice(0, 4)}-${rawCode.slice(4)}`;
  });
}

function isBadPin(value: string, avoidRepeated: boolean, avoidSequences: boolean, avoidDates: boolean) {
  const obviousBadPins = new Set(['000000', '111111', '123456', '654321', '121212', '010101']);

  if (obviousBadPins.has(value)) {
    return true;
  }

  if (avoidRepeated && /^(\d)\1+$/.test(value)) {
    return true;
  }

  if (avoidSequences && (isSimpleDigitSequence(value, 1) || isSimpleDigitSequence(value, -1) || /^(\d{2})\1+$/.test(value))) {
    return true;
  }

  return avoidDates && isDateLikePin(value);
}

function isSimpleDigitSequence(value: string, direction: 1 | -1) {
  return [...value].every((digit, index, digits) => {
    if (index === 0) {
      return true;
    }

    return Number(digit) === (Number(digits[index - 1]) + direction + 10) % 10;
  });
}

function isDateLikePin(value: string) {
  if (value.length !== 6 && value.length !== 8) {
    return false;
  }

  const chunks =
    value.length === 6
      ? [
          [value.slice(0, 2), value.slice(2, 4)],
          [value.slice(2, 4), value.slice(0, 2)],
        ]
      : [
          [value.slice(0, 2), value.slice(2, 4)],
          [value.slice(2, 4), value.slice(0, 2)],
          [value.slice(4, 6), value.slice(6, 8)],
        ];

  return chunks.some(([monthValue, dayValue]) => {
    const month = Number(monthValue);
    const day = Number(dayValue);

    return month >= 1 && month <= 12 && day >= 1 && day <= 31;
  });
}

function secureRandomInt(maxExclusive: number) {
  if (!Number.isInteger(maxExclusive) || maxExclusive <= 0 || maxExclusive > 0x100000000) {
    throw new Error('Invalid random range.');
  }

  const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
  const randomValue = new Uint32Array(1);

  while (true) {
    crypto.getRandomValues(randomValue);

    if (randomValue[0] < limit) {
      return randomValue[0] % maxExclusive;
    }
  }
}

function randomCharacter(characters: string) {
  return characters[secureRandomInt(characters.length)];
}

function shuffleCharacters(characters: string[]) {
  const shuffled = [...characters];

  for (let index = shuffled.length - 1; index > 0; index -= 1) {
    const swapIndex = secureRandomInt(index + 1);
    const current = shuffled[index];
    shuffled[index] = shuffled[swapIndex];
    shuffled[swapIndex] = current;
  }

  return shuffled;
}

function filterCharacters(characters: string, excludeSet: Set<string>) {
  return [...new Set([...characters].filter((character) => !excludeSet.has(character)))].join('');
}

export function estimatePasswordEntropy(length: number, poolLength: number) {
  return poolLength > 0 ? length * Math.log2(poolLength) : 0;
}

export function estimateRecoveryCodeEntropy(format: RecoveryCodeFormat) {
  // Eight random characters in one usable code; grouping contributes no randomness.
  return 8 * Math.log2(format === 'digits' ? 10 : 32);
}

export function estimatePassphraseEntropy(
  wordCount: number,
  capitalization: PassphraseCapitalization,
  addNumber: boolean,
  addSymbol: boolean
) {
  return (
    wordCount * Math.log2(passphraseWords.length) +
    (capitalization === 'random' ? wordCount : 0) +
    (addNumber ? Math.log2(10) : 0) +
    (addSymbol ? Math.log2(passwordCharacters.safeSymbols.length) : 0)
  );
}

export function getSecretStrength(entropy: number): SecretStrength {
  if (entropy < 40) {
    return { label: 'Very weak', className: 'bg-red-500/15 text-red-200 ring-1 ring-red-400/30', color: '#ef4444' };
  }

  if (entropy < 60) {
    return { label: 'Weak', className: 'bg-orange-500/15 text-orange-200 ring-1 ring-orange-400/30', color: '#f97316' };
  }

  if (entropy < 80) {
    return { label: 'Okay', className: 'bg-yellow-500/15 text-yellow-200 ring-1 ring-yellow-400/30', color: '#eab308' };
  }

  if (entropy < 120) {
    return { label: 'Strong', className: 'bg-emerald-500/15 text-emerald-200 ring-1 ring-emerald-400/30', color: '#22c55e' };
  }

  return { label: 'Very strong', className: 'bg-green-700/35 text-green-100 ring-1 ring-green-300/40', color: '#15803d' };
}

export function formatEntropy(entropy: number) {
  return `${entropy.toFixed(entropy >= 100 ? 0 : 1)} bits`;
}

export function getSecretModeLabel(mode: SecretMode) {
  const labels: Record<SecretMode, string> = {
    password: 'Password',
    passphrase: 'Passphrase',
    token: 'API key / token',
    pin: 'PIN',
    recovery: 'Recovery codes',
  };

  return labels[mode];
}

export function getSecretProfileLabel(
  mode: SecretMode,
  passwordOptions: PasswordOptions,
  tokenBits: TokenBits,
  tokenFormat: TokenFormat
) {
  if (mode === 'password') {
    return passwordPresetLabels[getMatchingPasswordPreset(passwordOptions)];
  }

  if (mode === 'token') {
    return tokenFormat === 'uuid' ? 'UUID v4' : `${tokenBits}-bit ${tokenFormat === 'hex' ? 'hex' : 'base64url'}`;
  }

  return getSecretModeLabel(mode);
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function bytesToBase64Url(bytes: Uint8Array) {
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('');

  return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
