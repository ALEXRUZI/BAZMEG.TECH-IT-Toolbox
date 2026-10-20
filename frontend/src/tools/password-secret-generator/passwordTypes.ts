export type SecretMode = 'password' | 'passphrase' | 'token' | 'pin' | 'recovery';
export type PasswordPresetId =
  | 'general'
  | 'strong'
  | 'very-strong'
  | 'practical'
  | 'readable'
  | 'compatible'
  | 'custom';
export type PassphraseSeparator = 'hyphen' | 'underscore' | 'dot' | 'space' | 'none';
export type PassphraseCapitalization = 'lowercase' | 'title' | 'random';
export type TokenBits = 128 | 192 | 256;
export type TokenFormat = 'base64url' | 'hex' | 'uuid';
export type RecoveryCodeCount = 5 | 10 | 20;
export type RecoveryCodeFormat = 'digits' | 'alphanumeric';

export type PasswordOptions = {
  preset: PasswordPresetId;
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  numbers: boolean;
  symbols: boolean;
  safeSymbolsOnly: boolean;
  avoidQwertyMismatch: boolean;
  avoidVisualSimilar: boolean;
  avoidQuoteLike: boolean;
  avoidDashUnderscore: boolean;
  avoidSlashBackslashPipe: boolean;
  avoidHardPunctuation: boolean;
  avoidShellSensitive: boolean;
  avoidJsonEnvSensitive: boolean;
  customExclude: string;
};

export type SecretStrength = {
  label: 'Very weak' | 'Weak' | 'Okay' | 'Strong' | 'Very strong';
  className: string;
  color: string;
};
