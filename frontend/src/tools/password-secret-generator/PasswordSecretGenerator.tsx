import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { useTextClipboard } from '../../components/useTextClipboard';

import { Field, Label, Panel, ResultItem, inputClass, FieldInput, FieldSelect } from '../../components/Panel';
import { formatEntropy, generatePassphrase, generatePassword, generatePin, generateRecoveryCodes, generateToken, getMatchingPasswordPreset, getSecretModeLabel, getSecretProfileLabel, getSecretStrength, estimatePassphraseEntropy, estimatePasswordEntropy, estimateRecoveryCodeEntropy, buildPasswordPool } from './passwordGenerator';
import { passwordPresetInfo, passwordPresetLabels, passwordPresets } from './passwordPresets';
import type { PassphraseCapitalization, PassphraseSeparator, PasswordOptions, PasswordPresetId, RecoveryCodeCount, RecoveryCodeFormat, SecretMode, TokenBits, TokenFormat } from './passwordTypes';

export function PasswordSecretGenerator() {
  const [mode, setMode] = useState<SecretMode>('password');
  const [passwordOptions, setPasswordOptions] = useState<PasswordOptions>({
    preset: 'general',
    ...passwordPresets.general,
  });
  const [isPresetInfoOpen, setIsPresetInfoOpen] = useState(false);
  const [passphraseWordCount, setPassphraseWordCount] = useState(4);
  const [passphraseSeparator, setPassphraseSeparator] = useState<PassphraseSeparator>('hyphen');
  const [passphraseCapitalization, setPassphraseCapitalization] = useState<PassphraseCapitalization>('lowercase');
  const [passphraseAddNumber, setPassphraseAddNumber] = useState(false);
  const [passphraseAddSymbol, setPassphraseAddSymbol] = useState(false);
  const [tokenBits, setTokenBits] = useState<TokenBits>(256);
  const [tokenFormat, setTokenFormat] = useState<TokenFormat>('base64url');
  const [pinDigits, setPinDigits] = useState(6);
  const [pinAvoidRepeated, setPinAvoidRepeated] = useState(true);
  const [pinAvoidSequences, setPinAvoidSequences] = useState(true);
  const [pinAvoidDates, setPinAvoidDates] = useState(true);
  const [recoveryCount, setRecoveryCount] = useState<RecoveryCodeCount>(10);
  const [recoveryFormat, setRecoveryFormat] = useState<RecoveryCodeFormat>('alphanumeric');
  const [generatedValue, setGeneratedValue] = useState('');
  const [generationError, setGenerationError] = useState('');
  const { copy, reset: resetCopy, copied, error: copyError } = useTextClipboard(generatedValue, mode === 'recovery' ? 'Copied all' : 'Copied');

  const passwordPool = buildPasswordPool(passwordOptions);
  const passwordEntropy = estimatePasswordEntropy(passwordOptions.length, passwordPool.length);
  const passwordStrength = getSecretStrength(passwordEntropy);
  const currentPasswordPreset = getMatchingPasswordPreset(passwordOptions);
  const currentEntropy =
    mode === 'password'
      ? passwordEntropy
      : mode === 'passphrase'
        ? estimatePassphraseEntropy(
            passphraseWordCount,
            passphraseCapitalization,
            passphraseAddNumber,
            passphraseAddSymbol
          )
        : mode === 'token'
          ? tokenFormat === 'uuid'
            ? 122
            : tokenBits
          : mode === 'pin'
            ? pinDigits * Math.log2(10)
            : estimateRecoveryCodeEntropy(recoveryFormat);
  const currentStrength = getSecretStrength(currentEntropy);
  const modeLabel = getSecretModeLabel(mode);

  useEffect(() => {
    regenerateSecret();
  }, [
    mode,
    passwordOptions,
    passphraseWordCount,
    passphraseSeparator,
    passphraseCapitalization,
    passphraseAddNumber,
    passphraseAddSymbol,
    tokenBits,
    tokenFormat,
    pinDigits,
    pinAvoidRepeated,
    pinAvoidSequences,
    pinAvoidDates,
    recoveryCount,
    recoveryFormat,
  ]);

  function updatePasswordOptions(nextOptions: Partial<PasswordOptions>) {
    setPasswordOptions((currentOptions) => {
      const updatedOptions = {
        ...currentOptions,
        ...nextOptions,
      };

      return {
        ...updatedOptions,
        preset: getMatchingPasswordPreset(updatedOptions),
      };
    });
  }

  function applyPasswordPreset(preset: PasswordPresetId) {
    setPasswordOptions({ preset, ...passwordPresets[preset] });
  }

  function avoidCommonConfusingCharacters() {
    updatePasswordOptions({
      avoidQwertyMismatch: true,
      avoidVisualSimilar: true,
      avoidQuoteLike: true,
      avoidDashUnderscore: true,
      avoidSlashBackslashPipe: true,
      avoidHardPunctuation: true,
    });
  }

  function regenerateSecret() {
    try {
      setGenerationError('');
      resetCopy();

      if (mode === 'password') {
        setGeneratedValue(generatePassword(passwordOptions));
      } else if (mode === 'passphrase') {
        setGeneratedValue(
          generatePassphrase(
            passphraseWordCount,
            passphraseSeparator,
            passphraseCapitalization,
            passphraseAddNumber,
            passphraseAddSymbol
          )
        );
      } else if (mode === 'token') {
        setGeneratedValue(generateToken(tokenBits, tokenFormat));
      } else if (mode === 'pin') {
        setGeneratedValue(generatePin(pinDigits, pinAvoidRepeated, pinAvoidSequences, pinAvoidDates));
      } else {
        setGeneratedValue(generateRecoveryCodes(recoveryCount, recoveryFormat).join('\n'));
      }
    } catch (error) {
      setGeneratedValue('');
      setGenerationError(error instanceof Error ? error.message : 'Could not generate a secret in this browser.');
    }
  }

  function copyGeneratedValue() {
    if (!generatedValue) {
      return;
    }

    void copy();
  }

  function clearGeneratedValue() {
    setGeneratedValue('');
    resetCopy();
  }

  return (
    <Panel title="Password / Secret Generator">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Generate passwords, passphrases, PINs, recovery codes, API keys, and tokens locally in your browser.
      </p>
      <div className="mt-4 rounded-2xl border border-emerald-400/20 bg-emerald-500/10 p-4 text-sm leading-6 text-emerald-100">
        Generated locally in your browser using the Web Crypto API. Nothing is sent to the server. Security still depends
        on your device, browser, screen, clipboard, extensions, and malware state.
      </div>

      <div className="mt-6 flex flex-wrap gap-2" aria-label="Secret type">
        {(['password', 'passphrase', 'token', 'pin', 'recovery'] as SecretMode[]).map((secretMode) => (
          <button
            key={secretMode}
            className={`rounded-full border px-4 py-2 text-sm font-semibold transition ${
              mode === secretMode
                ? 'border-emerald-400/60 bg-emerald-500/15 text-emerald-100'
                : 'border-white/10 bg-zinc-950/60 text-zinc-300 hover:border-emerald-400/40 hover:text-emerald-200'
            }`}
            type="button"
            onClick={() => setMode(secretMode)}
            aria-pressed={mode === secretMode}
          >
            {getSecretModeLabel(secretMode)}
          </button>
        ))}
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(320px,0.75fr)]">
        <div className="min-w-0">
          {mode === 'password' && (
            <div className="grid gap-5">
              <Field>
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <Label>Password preset</Label>
                  <button
                    className="rounded-xl border border-emerald-500/30 px-3 py-1.5 text-xs font-semibold text-emerald-300 transition hover:border-emerald-400 hover:bg-emerald-500/10"
                    type="button"
                    onClick={() => setIsPresetInfoOpen((isOpen) => !isOpen)}
                    aria-expanded={isPresetInfoOpen}
                    aria-controls="password-preset-info"
                  >
                    Preset info
                  </button>
                </div>
                <FieldSelect
                  className={inputClass()}
                  value={currentPasswordPreset}
                  onChange={(event) => applyPasswordPreset(event.target.value as PasswordPresetId)}
                >
                  {(Object.keys(passwordPresetLabels) as PasswordPresetId[]).map((preset) => (
                    <option key={preset} value={preset}>
                      {passwordPresetLabels[preset]}
                    </option>
                  ))}
                </FieldSelect>
              </Field>

              {isPresetInfoOpen && (
                <div
                  id="password-preset-info"
                  className="rounded-2xl border border-emerald-400/20 bg-zinc-950/60 p-4 text-sm leading-6 text-zinc-300"
                >
                  <div className="grid gap-3">
                    {(Object.keys(passwordPresetLabels) as PasswordPresetId[]).map((preset, index) => (
                      <div key={preset} className={index === 0 ? '' : 'border-t border-white/10 pt-3'}>
                        <p className="font-semibold text-zinc-100">{passwordPresetLabels[preset]}</p>
                        <p className="mt-1 text-zinc-300">{passwordPresetInfo[preset]}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {currentPasswordPreset === 'practical' && (
                <div className="rounded-2xl border border-emerald-400/20 bg-zinc-950/60 p-4 text-sm leading-6 text-zinc-300">
                  Uses uppercase, lowercase, numbers, and a limited safe-symbol set. Excludes common visual/keyboard
                  gotchas, quote-like characters, slash/backslash/pipe, whitespace, and shell/config-hostile symbols.
                  Length is increased automatically to keep entropy high.
                </div>
              )}

              <Field>
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <Label>Length: {passwordOptions.length}</Label>
                  <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${passwordStrength.className}`}>
                    {passwordStrength.label} | {formatEntropy(passwordEntropy)}
                  </span>
                </div>
                <FieldInput
                  className="w-full accent-emerald-500"
                  type="range"
                  min={6}
                  max={64}
                  value={passwordOptions.length}
                  style={{ accentColor: passwordStrength.color }}
                  onChange={(event) => updatePasswordOptions({ length: Number(event.target.value) })}
                />
              </Field>

              <div className="grid gap-3 sm:grid-cols-2">
                <SecretCheckbox
                  label="Lowercase"
                  checked={passwordOptions.lowercase}
                  onChange={(checked) => updatePasswordOptions({ lowercase: checked })}
                />
                <SecretCheckbox
                  label="Uppercase"
                  checked={passwordOptions.uppercase}
                  onChange={(checked) => updatePasswordOptions({ uppercase: checked })}
                />
                <SecretCheckbox
                  label="Numbers"
                  checked={passwordOptions.numbers}
                  onChange={(checked) => updatePasswordOptions({ numbers: checked })}
                />
                <SecretCheckbox
                  label="Symbols"
                  checked={passwordOptions.symbols}
                  onChange={(checked) => updatePasswordOptions({ symbols: checked })}
                />
              </div>

              <details className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
                <summary className="cursor-pointer text-sm font-semibold text-zinc-200">
                  Exclusions and compatibility details
                </summary>
                <div className="mt-4 grid gap-4">
                  <button
                    className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-emerald-200 transition hover:border-emerald-400 hover:bg-emerald-500/15"
                    type="button"
                    onClick={avoidCommonConfusingCharacters}
                  >
                    Avoid common confusing characters
                  </button>
                  <p className="text-xs leading-5 text-zinc-300">
                    Excluded characters reduce the character pool. Increase length to keep strength high.
                  </p>
                  <div className="grid gap-3">
                    <SecretCheckbox
                      label="Avoid QWERTY/QWERTZ mismatch"
                      detail={renderCharacterChips(['y', 'Y', 'z', 'Z'])}
                      checked={passwordOptions.avoidQwertyMismatch}
                      onChange={(checked) => updatePasswordOptions({ avoidQwertyMismatch: checked })}
                    />
                    <SecretCheckbox
                      label="Avoid visually similar characters"
                      detail={renderCharacterChips([
                        '0',
                        'O',
                        'o',
                        '1',
                        'l',
                        'I',
                        'i',
                        '|',
                        '5',
                        'S',
                        's',
                        '2',
                        'Z',
                        'z',
                        '8',
                        'B',
                        '6',
                        'G',
                      ])}
                      checked={passwordOptions.avoidVisualSimilar}
                      onChange={(checked) => updatePasswordOptions({ avoidVisualSimilar: checked })}
                    />
                    <SecretCheckbox
                      label="Avoid quote-like symbols"
                      detail={renderCharacterChips(['\'', '"', '`', '´', '‘', '’', '“', '”'])}
                      checked={passwordOptions.avoidQuoteLike}
                      onChange={(checked) => updatePasswordOptions({ avoidQuoteLike: checked })}
                    />
                    <SecretCheckbox
                      label="Avoid dash/underscore variants"
                      detail={renderCharacterChips(['-', '–', '—', '_'])}
                      checked={passwordOptions.avoidDashUnderscore}
                      onChange={(checked) => updatePasswordOptions({ avoidDashUnderscore: checked })}
                    />
                    <SecretCheckbox
                      label="Avoid slash/backslash/pipe"
                      detail={renderCharacterChips(['/', '\\', '|'])}
                      checked={passwordOptions.avoidSlashBackslashPipe}
                      onChange={(checked) => updatePasswordOptions({ avoidSlashBackslashPipe: checked })}
                    />
                    <SecretCheckbox
                      label="Avoid hard-to-read punctuation"
                      detail={renderCharacterChips(['.', ',', ';', ':'])}
                      checked={passwordOptions.avoidHardPunctuation}
                      onChange={(checked) => updatePasswordOptions({ avoidHardPunctuation: checked })}
                    />
                  </div>

                  <details className="rounded-xl border border-white/10 bg-zinc-950 p-4">
                    <summary className="cursor-pointer text-sm font-semibold text-zinc-200">
                      Advanced compatibility exclusions
                    </summary>
                    <div className="mt-4 grid gap-3">
                      <SecretCheckbox
                        label="Avoid shell-sensitive symbols"
                        detail={renderCharacterChips([
                          '$',
                          '`',
                          '"',
                          '\'',
                          '\\',
                          '!',
                          '&',
                          '|',
                          ';',
                          '<',
                          '>',
                          '(',
                          ')',
                          '[',
                          ']',
                          '{',
                          '}',
                          'space',
                        ])}
                        checked={passwordOptions.avoidShellSensitive}
                        onChange={(checked) => updatePasswordOptions({ avoidShellSensitive: checked })}
                      />
                      <SecretCheckbox
                        label="Avoid JSON/.env-sensitive symbols where practical"
                        detail={renderCharacterChips(['$', '`', '"', '\'', '\\', '{', '}', '=', ':', '#'])}
                        checked={passwordOptions.avoidJsonEnvSensitive}
                        onChange={(checked) => updatePasswordOptions({ avoidJsonEnvSensitive: checked })}
                      />
                      <SecretCheckbox
                        label="Use limited safe-symbol set"
                        checked={passwordOptions.safeSymbolsOnly}
                        onChange={(checked) => updatePasswordOptions({ safeSymbolsOnly: checked })}
                      />
                      <Field>
                        <Label>Custom exclude list</Label>
                        <FieldInput
                          className={inputClass()}
                          value={passwordOptions.customExclude}
                          onChange={(event) => updatePasswordOptions({ customExclude: event.target.value })}
                        />
                      </Field>
                    </div>
                  </details>
                </div>
              </details>
            </div>
          )}

          {mode === 'passphrase' && (
            <div className="grid gap-5">
              <Field>
                <Label>Word count: {passphraseWordCount}</Label>
                <FieldInput
                  className="w-full accent-emerald-500"
                  type="range"
                  min={3}
                  max={12}
                  value={passphraseWordCount}
                  style={{ accentColor: currentStrength.color }}
                  onChange={(event) => setPassphraseWordCount(Number(event.target.value))}
                />
              </Field>
              <div className="grid gap-4 md:grid-cols-2">
                <Field>
                  <Label>Separator</Label>
                  <FieldSelect
                    className={inputClass()}
                    value={passphraseSeparator}
                    onChange={(event) => setPassphraseSeparator(event.target.value as PassphraseSeparator)}
                  >
                    <option value="hyphen">Hyphen</option>
                    <option value="underscore">Underscore</option>
                    <option value="dot">Dot</option>
                    <option value="space">Space</option>
                    <option value="none">None</option>
                  </FieldSelect>
                </Field>
                <Field>
                  <Label>Capitalization</Label>
                  <FieldSelect
                    className={inputClass()}
                    value={passphraseCapitalization}
                    onChange={(event) => setPassphraseCapitalization(event.target.value as PassphraseCapitalization)}
                  >
                    <option value="lowercase">Lowercase</option>
                    <option value="title">Title Case</option>
                    <option value="random">Random case</option>
                  </FieldSelect>
                </Field>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <SecretCheckbox
                  label="Add number"
                  checked={passphraseAddNumber}
                  onChange={setPassphraseAddNumber}
                />
                <SecretCheckbox
                  label="Add symbol"
                  checked={passphraseAddSymbol}
                  onChange={setPassphraseAddSymbol}
                />
              </div>
            </div>
          )}

          {mode === 'token' && (
            <div className="grid gap-5">
              <div className="grid gap-4 md:grid-cols-2">
                <Field>
                  <Label>Strength / entropy</Label>
                  <FieldSelect
                    className={inputClass()}
                    value={tokenBits}
                    onChange={(event) => setTokenBits(Number(event.target.value) as TokenBits)}
                  >
                    <option value={128}>128-bit</option>
                    <option value={192}>192-bit</option>
                    <option value={256}>256-bit</option>
                  </FieldSelect>
                </Field>
                <Field>
                  <Label>Output format</Label>
                  <FieldSelect
                    className={inputClass()}
                    value={tokenFormat}
                    onChange={(event) => setTokenFormat(event.target.value as TokenFormat)}
                  >
                    <option value="base64url">Base64url without padding</option>
                    <option value="hex">Hex</option>
                    <option value="uuid">UUID v4</option>
                  </FieldSelect>
                </Field>
              </div>
              {tokenFormat === 'uuid' && (
                <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4 text-sm leading-6 text-zinc-400">
                  UUID v4 contains about 122 random bits. The 128/192/256-bit selector applies to base64url and hex
                  tokens.
                </div>
              )}
            </div>
          )}

          {mode === 'pin' && (
            <div className="grid gap-5">
              <Field>
                <Label>Digit count: {pinDigits}</Label>
                <FieldInput
                  className="w-full accent-emerald-500"
                  type="range"
                  min={4}
                  max={16}
                  value={pinDigits}
                  style={{ accentColor: currentStrength.color }}
                  onChange={(event) => setPinDigits(Number(event.target.value))}
                />
              </Field>
              <div className="grid gap-3">
                <SecretCheckbox label="Avoid repeated digits" checked={pinAvoidRepeated} onChange={setPinAvoidRepeated} />
                <SecretCheckbox label="Avoid simple sequences" checked={pinAvoidSequences} onChange={setPinAvoidSequences} />
                <SecretCheckbox label="Avoid date-like patterns" checked={pinAvoidDates} onChange={setPinAvoidDates} />
              </div>
            </div>
          )}

          {mode === 'recovery' && (
            <div className="grid gap-5">
              <div className="grid gap-4 md:grid-cols-2">
                <Field>
                  <label htmlFor="recovery-count" className="text-sm font-medium text-zinc-300">Code count</label>
                  <select
                    id="recovery-count"
                    className={inputClass()}
                    value={recoveryCount}
                    onChange={(event) => setRecoveryCount(Number(event.target.value) as RecoveryCodeCount)}
                  >
                    <option value={5}>5</option>
                    <option value={10}>10</option>
                    <option value={20}>20</option>
                  </select>
                </Field>
                <Field>
                  <label htmlFor="recovery-format" className="text-sm font-medium text-zinc-300">Format</label>
                  <select
                    id="recovery-format"
                    className={inputClass()}
                    value={recoveryFormat}
                    onChange={(event) => setRecoveryFormat(event.target.value as RecoveryCodeFormat)}
                  >
                    <option value="digits">Digits</option>
                    <option value="alphanumeric">Alphanumeric</option>
                  </select>
                </Field>
              </div>
              <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4 text-sm leading-6 text-zinc-400">
                Codes are grouped for display, for example 1234-5678. Copy all keeps the same grouped format.
                The hyphen adds no entropy. Each code is an individually usable one-time credential.
                Security depends on server-side online attempt limits, single-use enforcement, and secure storage.
                More simultaneously valid codes give an attacker more opportunities to guess one valid code;
                they do not strengthen each code. The per-code rating is not an authentication-system security
                verdict or a claim of offline-password-like security.
              </div>
            </div>
          )}
        </div>

        <div className="min-w-0 rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500">Generated output</p>
              <p className="mt-2 text-sm font-semibold text-zinc-200">{modeLabel}</p>
            </div>
            <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${currentStrength.className}`}>
              {currentStrength.label}{mode === 'recovery' ? ' per code' : ''}
            </span>
          </div>
          <p role="status" className={copyError ? 'mt-3 text-sm text-red-300' : 'sr-only'}>
            {copyError || (copied ? (mode === 'recovery' ? 'Copied all' : 'Copied') : '')}
          </p>
          <div className="mt-4 rounded-xl border border-white/10 bg-zinc-950 p-3">
            {generationError ? (
              <p className="text-sm leading-6 text-red-300">{generationError}</p>
            ) : generatedValue ? (
              <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words font-mono text-sm leading-6 text-emerald-200 [overflow-wrap:anywhere]">
                {generatedValue}
              </pre>
            ) : (
              <p className="text-sm leading-6 text-zinc-500">Cleared. Use Regenerate to create a new value.</p>
            )}
          </div>
          <div className="mt-4 grid gap-3 sm:grid-cols-3">
            <button
              className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-emerald-200 transition hover:border-emerald-400 hover:bg-emerald-500/15"
              type="button"
              onClick={regenerateSecret}
            >
              {mode === 'recovery' ? 'Regenerate all' : 'Regenerate'}
            </button>
            <button
              className="rounded-xl border border-emerald-500/30 px-4 py-2 text-sm font-semibold text-emerald-300 transition hover:border-emerald-400 hover:bg-emerald-500/10 disabled:cursor-not-allowed disabled:opacity-50"
              type="button"
              onClick={copyGeneratedValue}
              disabled={!generatedValue || Boolean(generationError)}
            >
              {copied ? (mode === 'recovery' ? 'Copied all' : 'Copied') : (mode === 'recovery' ? 'Copy all' : 'Copy')}
            </button>
            <button
              className="rounded-xl border border-white/10 px-4 py-2 text-sm font-semibold text-zinc-300 transition hover:border-red-400/50 hover:text-red-200"
              type="button"
              onClick={clearGeneratedValue}
            >
              Clear
            </button>
          </div>
          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            <ResultItem label="Profile" value={getSecretProfileLabel(mode, passwordOptions, tokenBits, tokenFormat)} />
            <ResultItem label={mode === 'recovery' ? 'Entropy per code' : 'Entropy estimate'} value={formatEntropy(currentEntropy)} />
          </div>
        </div>
      </div>
    </Panel>
  );
}

function SecretCheckbox({
  label,
  detail,
  checked,
  onChange,
}: {
  label: ReactNode;
  detail?: ReactNode;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className="flex items-start gap-3 rounded-xl border border-white/10 bg-zinc-950/60 p-3 text-sm leading-6 text-zinc-300">
      <input
        className="mt-1 size-4 accent-emerald-500"
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
      />
      <span className="min-w-0">
        <span>{label}</span>
        {detail && (
          <span className="mt-2 block min-w-0">
            {detail}
          </span>
        )}
      </span>
    </label>
  );
}

function renderCharacterChips(items: string[]) {
  return (
    <span className="flex min-w-0 flex-wrap gap-1.5" aria-label={`Excluded characters: ${items.join(' ')}`}>
      {items.map((item, index) => (
        <span
          key={`${item}-${index}`}
          className="inline-flex max-w-full items-center rounded-lg border border-emerald-400/25 bg-emerald-500/10 px-2 py-1 font-mono text-xs font-semibold leading-none text-zinc-100 shadow-sm shadow-black/20"
          title={item === 'space' ? 'space character' : item}
        >
          {item}
        </span>
      ))}
    </span>
  );
}
