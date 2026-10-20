import { Field, FieldInput, FieldError, Label, inputClass } from '../../components/Panel';
import type { ExportOptions } from './sshTypes';
import { historicalEncryptionAcknowledgment, ssh1Explanation } from './sshAlgorithms';
export function SshProtection({ options, change, disabled }: { options: ExportOptions; change: (value: ExportOptions) => void; disabled: boolean }) {
  const mismatch = options.passphrase !== options.confirmation ? 'Passphrase confirmation does not match.' : undefined;
  return <fieldset disabled={disabled} className="space-y-3 rounded-2xl border border-white/10 p-4">
    <legend className="px-2 text-sm font-semibold">Private-key protection</legend>
    <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={options.protected} onChange={e => change({ ...options, protected: e.target.checked, passphrase: '', confirmation: '', unencryptedAcknowledged: false, historicalEncryptionAcknowledged: false })} />Protect private keys with a passphrase</label>
    {options.protected ? <>
      {options.formats.includes('ssh1') ? <div className="space-y-2 text-sm text-red-300"><p role="alert">{ssh1Explanation}</p><label className="flex items-center gap-2"><input type="checkbox" checked={options.historicalEncryptionAcknowledged ?? false} onChange={e => change({ ...options, historicalEncryptionAcknowledged: e.target.checked })} />{historicalEncryptionAcknowledgment}</label></div> : <p className="text-xs text-zinc-400">Use a long, random passphrase. OpenSSH: bcrypt PBKDF, 32 rounds, AES-256-CTR. PPK v3: Argon2id, 64 MiB, 3 passes, 1 lane, AES-256-CBC + HMAC-SHA-256. No downgrade or recovery.</p>}
      <div className="grid gap-3 sm:grid-cols-2">
        <Field><Label>Output passphrase</Label><FieldInput className={inputClass()} type="password" autoComplete="off" maxLength={1024} value={options.passphrase} onChange={e => change({ ...options, passphrase: e.target.value })} /></Field>
        <Field error={mismatch}><Label>Confirm output passphrase</Label><FieldInput className={inputClass(Boolean(mismatch))} type="password" autoComplete="off" maxLength={1024} value={options.confirmation} onChange={e => change({ ...options, confirmation: e.target.value })} /><FieldError /></Field>
      </div>
    </> : <div className="space-y-2 text-sm text-red-300"><p>Stolen unencrypted private keys can authenticate wherever their public key is authorized.</p><label className="flex items-center gap-2"><input type="checkbox" checked={options.unencryptedAcknowledged} onChange={e => change({ ...options, unencryptedAcknowledged: e.target.checked })} />I deliberately choose unencrypted private-key output.</label></div>}
  </fieldset>;
}
