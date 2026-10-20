import { useId, useState } from 'react';

import { CommandBlock } from '../../components/CommandBlock';
import { Field, Label, Panel, inputClass, FieldInput, FieldSelect, FieldError, FieldDescription } from '../../components/Panel';
import {
  csrExampleDomain,
  csrExampleCountry,
  getCsrKeySizeNotes,
  csrSanLimit,
  csrExampleAdditionalDomain,
  csrKeyProfiles,
  csrHashOptions,
  csrOutputFormatLabels,
  privateKeyOutputFormatLabels,
  csrSignatureHashNotes,
} from './csrConstants';
import type {
  CsrKeyType,
  CsrSignatureHash,
  CsrOutputFormat,
  PrivateKeyOutputFormat,
  CsrSanEntry,
  CsrGeneratedOutput,
} from './csrTypes';
import {
  validateCsrCommonName,
  validateCsrCountry,
  validateCsrEmail,
  validateCsrSan,
  getCsrSanWarning,
} from './csrValidation';
import { createCsr } from './csrCrypto';

export function CsrGenerator() {
  const [commonName, setCommonName] = useState(csrExampleDomain);
  const [isCommonNameExample, setIsCommonNameExample] = useState(true);
  const [organization, setOrganization] = useState('');
  const [organizationalUnit, setOrganizationalUnit] = useState('');
  const [email, setEmail] = useState('');
  const [country, setCountry] = useState(csrExampleCountry);
  const [isCountryExample, setIsCountryExample] = useState(true);
  const [locality, setLocality] = useState('');
  const [state, setState] = useState('');
  const [keyType, setKeyType] = useState<CsrKeyType>('rsa');
  const [keySize, setKeySize] = useState('2048');
  const [signatureHash, setSignatureHash] = useState<CsrSignatureHash>('SHA-256');
  const [csrOutputFormat, setCsrOutputFormat] = useState<CsrOutputFormat>('pem-pkcs10');
  const [privateKeyOutputFormat, setPrivateKeyOutputFormat] = useState<PrivateKeyOutputFormat>('pkcs8-pem');
  const [privateKeyPassword, setPrivateKeyPassword] = useState('');
  const [isAdvancedExportOpen, setIsAdvancedExportOpen] = useState(false);
  const [sans, setSans] = useState<CsrSanEntry[]>([{ id: 1, value: csrExampleDomain, isExample: true }]);
  const [isGenerating, setIsGenerating] = useState(false);
  const [generationError, setGenerationError] = useState('');
  const [output, setOutput] = useState<CsrGeneratedOutput | null>(null);

  const formId = useId();
  const commonNameError = validateCsrCommonName(commonName);
  const countryError = validateCsrCountry(country);
  const emailError = validateCsrEmail(email);
  const sanErrors = sans.map((san) => validateCsrSan(san.value));
  const sanWarnings = sans.map((san) => getCsrSanWarning(san.value));
  const hasSanError = sanErrors.some(Boolean);
  const hasRequiredSan = sans.some((san) => san.value.trim());
  const privateKeyPasswordError =
    privateKeyOutputFormat === 'encrypted-pkcs8-pem' && !privateKeyPassword
      ? 'Password is required for encrypted private key export.'
      : '';
  const canGenerate =
    !commonNameError &&
    !countryError &&
    !emailError &&
    !privateKeyPasswordError &&
    hasRequiredSan &&
    !hasSanError &&
    !isGenerating;
  const selectedKeySizeNotes = getCsrKeySizeNotes(keyType);

  const addSan = () => {
    if (sans.length >= csrSanLimit) {
      return;
    }

    setSans((currentSans) => [
      ...currentSans,
      { id: Date.now(), value: csrExampleAdditionalDomain, isExample: true },
    ]);
  };
  const removeSan = (id: number) => {
    setSans((currentSans) => {
      const sanIndex = currentSans.findIndex((san) => san.id === id);

      return sanIndex <= 0 ? currentSans : currentSans.filter((san) => san.id !== id);
    });
  };
  const updateSan = (id: number, value: string) => {
    const sanIndex = sans.findIndex((san) => san.id === id);

    if (sanIndex === 0) {
      setCommonName(value);
      setIsCommonNameExample(false);
    }

    setSans((currentSans) =>
      currentSans.map((san) => (san.id === id ? { ...san, value, isExample: false } : san))
    );
  };
  const focusSan = (id: number) => {
    const sanIndex = sans.findIndex((san) => san.id === id);
    const selectedSan = sans[sanIndex];

    if (sanIndex === 0 && selectedSan?.isExample) {
      setCommonName('');
      setIsCommonNameExample(false);
    }

    setSans((currentSans) =>
      currentSans.map((san) => (san.id === id && san.isExample ? { ...san, value: '', isExample: false } : san))
    );
  };
  const blurSan = (id: number, index: number) => {
    setSans((currentSans) =>
      currentSans.map((san) =>
        san.id === id && !san.value.trim()
          ? { ...san, value: index === 0 ? csrExampleDomain : csrExampleAdditionalDomain, isExample: true }
          : san
      )
    );

    if (index === 0) {
      const firstSan = sans.find((san) => san.id === id);

      if (firstSan && !firstSan.value.trim()) {
        setCommonName(csrExampleDomain);
        setIsCommonNameExample(true);
      }
    }
  };
  const setCommonNameAndFirstSan = (value: string, isExample: boolean) => {
    setCommonName(value);
    setIsCommonNameExample(isExample);
    setSans((currentSans) =>
      currentSans.map((san, index) => (index === 0 ? { ...san, value, isExample } : san))
    );
  };
  const changeKeyType = (nextKeyType: CsrKeyType) => {
    setKeyType(nextKeyType);
    setKeySize(csrKeyProfiles[nextKeyType].sizes[0]);

    if (nextKeyType === 'rsa' && privateKeyOutputFormat === 'traditional-ec-pem') {
      setPrivateKeyOutputFormat('pkcs8-pem');
    }

    if (nextKeyType === 'ec' && privateKeyOutputFormat === 'traditional-rsa-pem') {
      setPrivateKeyOutputFormat('pkcs8-pem');
    }
  };

  async function generateCsr() {
    if (!canGenerate) {
      setGenerationError('Fix the highlighted fields before generating the CSR.');
      return;
    }

    setIsGenerating(true);
    setGenerationError('');

    try {
      const generatedOutput = await createCsr({
        commonName: commonName.trim(),
        organization: organization.trim(),
        organizationalUnit: organizationalUnit.trim(),
        email: email.trim(),
        country: country.trim().toUpperCase(),
        locality: locality.trim(),
        state: state.trim(),
        keyType,
        keySize,
        signatureHash,
        csrOutputFormat,
        privateKeyOutputFormat,
        privateKeyPassword,
        sans: sans.map((san) => san.value.trim()).filter(Boolean),
      });

      setOutput(generatedOutput);
    } catch (error) {
      setGenerationError(error instanceof Error ? error.message : 'The browser could not generate this CSR.');
    } finally {
      setIsGenerating(false);
    }
  }

  return (
    <Panel title="CSR Generator">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Generate the private key, public key, and CSR on the browser side only. Nothing is sent to a server, so the key
        material stays on your workstation/browser session as long as your client device is trusted.
      </p>
      <p className="mt-3 text-xs font-semibold uppercase tracking-[0.2em] text-emerald-300">
        Fields marked with * are required. Unmarked fields are optional.
      </p>
      <div className="mt-6 grid gap-6 xl:grid-cols-[1fr_0.8fr]">
        <div className="grid gap-4">
          <Field error={commonNameError}>
            <Label>CN / Common Name *</Label>
            <FieldInput
              className={inputClass(Boolean(commonNameError), isCommonNameExample)}
              value={commonName}
              onFocus={() => {
                if (isCommonNameExample) {
                  setCommonNameAndFirstSan('', false);
                }
              }}
              onChange={(event) => {
                setCommonNameAndFirstSan(event.target.value, false);
              }}
              onBlur={() => {
                if (!commonName.trim()) {
                  setCommonNameAndFirstSan(csrExampleDomain, true);
                }
              }}
            />
            <FieldError />
          </Field>
          <fieldset className="space-y-2">
            <legend className="sr-only">SANs / DNS names / IPs *</legend>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <span className="text-sm font-medium text-zinc-300" aria-hidden="true">SANs / DNS names / IPs *</span>
              <button
                className="rounded-lg border border-emerald-500/30 px-3 py-1 text-sm font-semibold text-emerald-300 transition hover:border-emerald-400 hover:bg-emerald-500/10 disabled:cursor-not-allowed disabled:opacity-50"
                type="button"
                onClick={addSan}
                aria-label="Add SAN"
                disabled={sans.length >= csrSanLimit}
              >
                +
              </button>
            </div>
            <div className="grid gap-2">
              {sans.map((san, index) => (
                <Field key={san.id} error={sanErrors[index]} description={!sanErrors[index] ? sanWarnings[index] : undefined}>
                  <div className="grid gap-2 sm:grid-cols-[1fr_auto]">
                    <Label className="sr-only">SAN {index + 1}</Label>
                    <FieldInput
                      aria-invalid={Boolean(sanErrors[index]) || (!hasRequiredSan && index === 0)}
                      aria-describedby={[`${formId}-san-help`, `${formId}-san-ip-help`, !hasRequiredSan && index === 0 && `${formId}-san-required`].filter(Boolean).join(' ')}
                      className={inputClass(Boolean(sanErrors[index]), san.isExample)}
                      placeholder={index === 0 ? csrExampleDomain : 'www.example.com or 10.10.10.10'}
                      value={san.value}
                      onFocus={() => focusSan(san.id)}
                      onChange={(event) => updateSan(san.id, event.target.value)}
                      onBlur={() => blurSan(san.id, index)}
                    />
                    <button
                      className="rounded-lg border border-white/10 px-3 py-2 text-sm font-semibold text-zinc-300 transition hover:border-red-400/50 hover:text-red-200 disabled:cursor-not-allowed disabled:opacity-40"
                      type="button"
                      onClick={() => removeSan(san.id)}
                      aria-label={`Remove SAN ${index + 1}`}
                      disabled={index === 0}
                    >
                      Remove
                    </button>
                    <FieldError className="sm:col-span-2" />
                    {!sanErrors[index] && <FieldDescription className="text-amber-300 sm:col-span-2" />}
                  </div>
                </Field>
              ))}
            </div>
            {!hasRequiredSan && <p id={`${formId}-san-required`} className="text-xs leading-5 text-red-300">At least one SAN is required.</p>}
            <p id={`${formId}-san-help`} className="text-xs leading-5 text-zinc-500">
              Public TLS certificates must include at least one DNS name or IP address in SAN. The CA/B Forum Baseline
              Requirements do not define a universal SAN count maximum, so this form caps entries at {csrSanLimit}; your
              CA product may allow fewer.
            </p>
            <p id={`${formId}-san-ip-help`} className="text-xs leading-5 text-zinc-500">
              IP addresses are encoded as IP Address SAN entries, not DNS entries. Public CAs may include IP SANs only for
              public IPs that you can validate/control. Private/internal IPs such as 10.x.x.x, 172.16-31.x.x,
              192.168.x.x, localhost, and link-local addresses are not suitable for public CA certificates. For internal
              IPs, use an internal/private CA.
            </p>
          </fieldset>
          <div className="grid gap-4 md:grid-cols-2">
            <Field>
              <Label>Organization</Label>
              <FieldInput
                className={inputClass()}
                value={organization}
                onChange={(event) => setOrganization(event.target.value)}
              />
            </Field>
            <Field>
              <Label>Organizational Unit</Label>
              <FieldInput
                className={inputClass()}
                value={organizationalUnit}
                onChange={(event) => setOrganizationalUnit(event.target.value)}
              />
            </Field>
            <Field>
              <label htmlFor="csr-email" className="text-sm font-medium text-zinc-300">Email</label>
              <input
                id="csr-email"
                aria-invalid={Boolean(emailError)}
                aria-describedby={emailError ? 'csr-email-error' : undefined}
                className={inputClass(Boolean(emailError))}
                value={email}
                onChange={(event) => setEmail(event.target.value)}
              />
              {emailError && <p id="csr-email-error" role="alert" className="text-xs leading-5 text-red-300">{emailError}</p>}
            </Field>
            <Field error={countryError}>
              <Label>Country *</Label>
              <FieldInput
                className={inputClass(Boolean(countryError), isCountryExample)}
                maxLength={2}
                value={country}
                onFocus={() => {
                  if (isCountryExample) {
                    setCountry('');
                    setIsCountryExample(false);
                  }
                }}
                onChange={(event) => {
                  setCountry(event.target.value.toUpperCase());
                  setIsCountryExample(false);
                }}
                onBlur={() => {
                  if (!country.trim()) {
                    setCountry(csrExampleCountry);
                    setIsCountryExample(true);
                  }
                }}
              />
              <FieldError />
            </Field>
            <Field>
              <Label>State / Province</Label>
              <FieldInput className={inputClass()} value={state} onChange={(event) => setState(event.target.value)} />
            </Field>
            <Field>
              <Label>Locality / City</Label>
              <FieldInput
                className={inputClass()}
                value={locality}
                onChange={(event) => setLocality(event.target.value)}
              />
            </Field>
          </div>
          <div className="grid gap-4 md:grid-cols-3">
            <Field>
              <Label>Key type *</Label>
              <FieldSelect
                className={inputClass()}
                value={keyType}
                onChange={(event) => changeKeyType(event.target.value as CsrKeyType)}
              >
                <option value="rsa">RSA</option>
                <option value="ec">ECDSA</option>
              </FieldSelect>
            </Field>
            <Field>
              <Label>Key size *</Label>
              <FieldSelect className={inputClass()} value={keySize} onChange={(event) => setKeySize(event.target.value)}>
                {csrKeyProfiles[keyType].sizes.map((size) => (
                  <option key={size} value={size}>
                    {size}
                  </option>
                ))}
              </FieldSelect>
            </Field>
            <Field>
              <Label>Signature hash</Label>
              <FieldSelect
                className={inputClass()}
                value={signatureHash}
                onChange={(event) => setSignatureHash(event.target.value as CsrSignatureHash)}
              >
                {csrHashOptions.map((hash) => (
                  <option key={hash} value={hash}>
                    {hash}
                  </option>
                ))}
              </FieldSelect>
            </Field>
          </div>
          <button
            className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm font-semibold text-emerald-200 transition hover:border-emerald-400 hover:bg-emerald-500/15 disabled:cursor-not-allowed disabled:opacity-50"
            type="button"
            onClick={generateCsr}
            disabled={!canGenerate}
          >
            {isGenerating ? 'Generating...' : 'Generate private key and CSR'}
          </button>
          <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4 text-sm leading-6 text-zinc-300">
            <p>
              This tool generates a PEM-encoded PKCS#10 CSR and a PEM-encoded PKCS#8 private key by default.
            </p>
            <p className="mt-3 text-zinc-400">
              Use Advanced export format if you need DER, encrypted PKCS#8, or a traditional RSA/EC private key format.
            </p>
          </div>
          <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
            <button
              className="flex w-full items-center justify-between gap-4 text-left"
              type="button"
              onClick={() => setIsAdvancedExportOpen((isOpen) => !isOpen)}
              aria-expanded={isAdvancedExportOpen}
            >
              <span>
                <span className="block text-lg font-semibold">Advanced export format</span>
                <span className="mt-1 block text-sm leading-6 text-zinc-500">
                  {csrOutputFormatLabels[csrOutputFormat]} / {privateKeyOutputFormatLabels[privateKeyOutputFormat]}
                </span>
              </span>
              <span className="rounded-lg border border-emerald-500/30 px-3 py-1 text-sm font-semibold text-emerald-300">
                {isAdvancedExportOpen ? 'Hide' : 'Show'}
              </span>
            </button>
            {isAdvancedExportOpen && (
              <div className="mt-4 grid gap-5">
                <fieldset>
                  <legend className="text-sm font-semibold text-zinc-200">CSR output format</legend>
                  <div className="mt-3 grid gap-2 text-sm text-zinc-300">
                    <label className="flex items-start gap-3">
                      <input
                        className="mt-1 accent-emerald-400"
                        type="radio"
                        name={`${formId}-csr-format`}
                        checked={csrOutputFormat === 'pem-pkcs10'}
                        onChange={() => setCsrOutputFormat('pem-pkcs10')}
                      />
                      <span>PEM / PKCS#10 <span className="text-zinc-500">recommended</span></span>
                    </label>
                    <label className="flex items-start gap-3">
                      <input
                        className="mt-1 accent-emerald-400"
                        type="radio"
                        name={`${formId}-csr-format`}
                        checked={csrOutputFormat === 'der-pkcs10'}
                        onChange={() => setCsrOutputFormat('der-pkcs10')}
                      />
                      <span>DER / PKCS#10 <span className="text-zinc-500">binary, advanced</span></span>
                    </label>
                  </div>
                </fieldset>
                <fieldset>
                  <legend className="text-sm font-semibold text-zinc-200">Private key output format</legend>
                  <div className="mt-3 grid gap-2 text-sm text-zinc-300">
                    <label className="flex items-start gap-3">
                      <input
                        className="mt-1 accent-emerald-400"
                        type="radio"
                        name={`${formId}-key-format`}
                        checked={privateKeyOutputFormat === 'pkcs8-pem'}
                        onChange={() => setPrivateKeyOutputFormat('pkcs8-pem')}
                      />
                      <span>PKCS#8 PEM <span className="text-zinc-500">recommended</span></span>
                    </label>
                    <label className="flex items-start gap-3">
                      <input
                        className="mt-1 accent-emerald-400"
                        type="radio"
                        name={`${formId}-key-format`}
                        checked={privateKeyOutputFormat === 'encrypted-pkcs8-pem'}
                        onChange={() => setPrivateKeyOutputFormat('encrypted-pkcs8-pem')}
                      />
                      <span>Encrypted PKCS#8 PEM <span className="text-zinc-500">password protected</span></span>
                    </label>
                    <label className="flex items-start gap-3">
                      <input
                        className="mt-1 accent-emerald-400 disabled:cursor-not-allowed"
                        type="radio"
                        name={`${formId}-key-format`}
                        checked={privateKeyOutputFormat === 'traditional-rsa-pem'}
                        onChange={() => setPrivateKeyOutputFormat('traditional-rsa-pem')}
                        disabled={keyType !== 'rsa'}
                      />
                      <span>Traditional RSA PEM <span className="text-zinc-500">compatibility, RSA only</span></span>
                    </label>
                    <label className="flex items-start gap-3">
                      <input
                        className="mt-1 accent-emerald-400 disabled:cursor-not-allowed"
                        type="radio"
                        name={`${formId}-key-format`}
                        checked={privateKeyOutputFormat === 'traditional-ec-pem'}
                        onChange={() => setPrivateKeyOutputFormat('traditional-ec-pem')}
                        disabled={keyType !== 'ec'}
                      />
                      <span>Traditional EC PEM <span className="text-zinc-500">compatibility, ECDSA only</span></span>
                    </label>
                    <label className="flex items-start gap-3">
                      <input
                        className="mt-1 accent-emerald-400"
                        type="radio"
                        name={`${formId}-key-format`}
                        checked={privateKeyOutputFormat === 'pkcs8-der'}
                        onChange={() => setPrivateKeyOutputFormat('pkcs8-der')}
                      />
                      <span>PKCS#8 DER <span className="text-zinc-500">binary, advanced</span></span>
                    </label>
                  </div>
                </fieldset>
                {privateKeyOutputFormat === 'encrypted-pkcs8-pem' && (
                  <Field error={privateKeyPasswordError}>
                    <Label>Encryption password *</Label>
                    <FieldInput
                      className={inputClass(Boolean(privateKeyPasswordError))}
                      type="password"
                      value={privateKeyPassword}
                      onChange={(event) => setPrivateKeyPassword(event.target.value)}
                    />
                    <FieldError />
                  </Field>
                )}
              </div>
            )}
          </div>
          {generationError && <p className="text-sm leading-6 text-red-300">{generationError}</p>}
        </div>
        <aside className="grid content-start gap-4">
          <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
            <p className="text-sm font-semibold text-zinc-200">Typical choices</p>
            <div className="mt-3 space-y-4 text-sm leading-6 text-zinc-400">
              <div>
                <p className="font-semibold text-zinc-300">Key type</p>
                <p>{csrKeyProfiles.rsa.typical}</p>
                <p>{csrKeyProfiles.ec.typical}</p>
              </div>
              <div>
                <p className="font-semibold text-zinc-300">Key size</p>
                {csrKeyProfiles[keyType].sizes.map((size) => (
                  <p key={size}>{selectedKeySizeNotes[size]}</p>
                ))}
              </div>
              <div>
                <p className="font-semibold text-zinc-300">Signature hash</p>
                {csrHashOptions.map((hash) => (
                  <p key={hash}>{csrSignatureHashNotes[hash]}</p>
                ))}
              </div>
            </div>
          </div>
          <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/10 p-4 text-sm leading-6 text-emerald-100">
            Private keys are sensitive. Copy the key only to the system that will terminate TLS, and do not paste it into
            ticket systems, chat, or email.
          </div>
        </aside>
      </div>
      {output && (
        <div className="mt-6 grid gap-4">
          <div>
            <h3 className="text-lg font-semibold">{output.csrFileName}</h3>
            <p className="mt-2 text-sm leading-6 text-zinc-400">{csrOutputFormatLabels[csrOutputFormat]}</p>
            <CommandBlock>{output.csrOutput}</CommandBlock>
          </div>
          <div>
            <h3 className="text-lg font-semibold">{output.privateKeyFileName}</h3>
            <p className="mt-2 text-sm leading-6 text-zinc-400">{privateKeyOutputFormatLabels[privateKeyOutputFormat]}</p>
            <CommandBlock>{output.privateKeyOutput}</CommandBlock>
          </div>
          <div>
            <h3 className="text-lg font-semibold">{output.publicKeyFileName}</h3>
            <p className="mt-2 text-sm leading-6 text-zinc-400">
              The public key is typically not submitted to the CA because it is already inside the CSR. It can be useful
              for key-pair checks, pinning workflows, inventory records, or systems that ask you to upload a public key
              separately.
            </p>
            <CommandBlock>{output.publicKeyPem}</CommandBlock>
          </div>
        </div>
      )}
    </Panel>
  );
}
