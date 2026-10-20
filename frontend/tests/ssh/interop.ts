import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import type { Result } from '../../src/tools/ssh-key-generator/sshTypes';

export function requireSafe(condition: unknown, message: string): asserts condition { if (!condition) throw new Error(message); }
export const puttygen = process.env.SSH_PUTTYGEN || 'puttygen';
export function native(executable: string, args: string[]): string {
  try { return execFileSync(executable, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 120_000, maxBuffer: 128 * 1024 }); }
  catch { throw new Error('Independent SSH tool operation failed (secret-bearing command/output suppressed).'); }
}
export function disposable<T>(use: (directory: string) => T): T {
  const directory = mkdtempSync(join(existsSync('/tmp/opencode') ? '/tmp/opencode' : tmpdir(), 'ssh-interop-'));
  try { return use(directory); } finally { rmSync(directory, { recursive: true, force: true }); }
}
export function verifyNative(result: Result, passphrase: string, verifyPpk = true): void {
  disposable(directory => {
    const rsa1 = result.outputs.some(output => output.format === 'ssh1');
    const expected = result.outputs.find(output => output.format === 'public')?.text.trim().split(/\s+/).slice(0, rsa1 ? 3 : 2).join(' ');
    requireSafe(expected, 'Missing public output.');
    const ed448 = expected.startsWith('ssh-ed448 ');
    const puttyOnly = ed448 || expected.startsWith('ssh-dss ') || result.outputs[0]?.filename.includes('rsa512') || result.outputs[0]?.filename.includes('rsa768');
    const passwordFile = join(directory, 'passphrase'); writeFileSync(passwordFile, `${passphrase}\n`, { mode: 0o600 });
    for (const output of result.outputs.filter(item => item.private)) {
      const path = join(directory, output.filename); writeFileSync(path, output.bytes ?? output.text, { mode: 0o600 });
      let pub: string;
      if (output.format === 'ssh1') {
        if (!verifyPpk) continue;
        pub = native(puttygen, [path, '-L', '--old-passphrase', passwordFile]);
        requireSafe(native(puttygen, [path, '-l']).includes(result.inspector.fingerprint.replace(/^MD5:/, '')), 'SSH-1 historical fingerprint differs.');
      } else if (output.format === 'openssh') {
        if (puttyOnly) { if (!verifyPpk) continue; pub = native(puttygen, [path, '-L', '--old-passphrase', passwordFile]); }
        else pub = native('ssh-keygen', ['-y', '-P', passphrase, '-f', path]);
      }
      else {
        if (!verifyPpk) continue;
        pub = native(puttygen, [path, '-L', '--old-passphrase', passwordFile]);
        if (ed448) {
          // Standard OpenSSH has no Ed448 support. Do not qualify PuTTY's speculative wrapper.
          const rewritten = join(directory, 'putty-reencrypted');
          native(puttygen, [path, '--old-passphrase', passwordFile, '--new-passphrase', passwordFile, '--reencrypt', '--ppk-param', 'version=3,kdf=argon2id,memory=65536,passes=3,parallelism=1', '-o', rewritten]);
          requireSafe(native(puttygen, [rewritten, '-L', '--old-passphrase', passwordFile]).trim().split(/\s+/).slice(0, 2).join(' ') === expected, 'PuTTY-reencrypted Ed448 identity differs.');
          requireSafe(native(puttygen, [rewritten, '-l', '-E', 'sha256']).includes(result.inspector.fingerprint), 'PuTTY Ed448 SHA-256 fingerprint differs.');
        } else {
          const openssh = join(directory, 'putty-export');
          native(puttygen, [path, '--old-passphrase', passwordFile, '--new-passphrase', passwordFile, '-O', 'private-openssh-new', '-o', openssh]);
          requireSafe(native(puttyOnly ? puttygen : 'ssh-keygen', puttyOnly ? [openssh, '-L', '--old-passphrase', passwordFile] : ['-y', '-P', passphrase, '-f', openssh]).trim().split(/\s+/).slice(0, 2).join(' ') === expected, 'PuTTY-exported OpenSSH identity differs.');
        }
      }
      requireSafe(pub.trim().split(/\s+/).slice(0, rsa1 ? 3 : 2).join(' ') === expected, 'Independent public-key identity differs.');
    }
    const publicFile = join(directory, 'public.pub'); writeFileSync(publicFile, result.outputs.find(output => output.format === 'public')!.text, { mode: 0o600 });
    if (!rsa1) {
      if (puttyOnly) { if (verifyPpk) requireSafe(native(puttygen, [publicFile, '-l', '-E', 'sha256']).includes(result.inspector.fingerprint), 'PuTTY SHA-256 fingerprint differs.'); }
      else requireSafe(native('ssh-keygen', ['-lf', publicFile, '-E', 'sha256']).includes(result.inspector.fingerprint), 'Independent SHA-256 fingerprint differs.');
    }
  });
}
export function independentFixture(id: string, encrypted: boolean, format: 'openssh' | 'ppk', variant?: string): { text: string; passphrase: string; publicLine: string } {
  return disposable(directory => {
    const passphrase = encrypted ? randomBytes(24).toString('base64url') : '', passwordFile = join(directory, 'password');
    writeFileSync(passwordFile, `${passphrase}\n`, { mode: 0o600 });
    const path = join(directory, 'key'), comment = 'Independent Próba "comment" \\ @test';
    requireSafe(id !== 'ed448' || format === 'ppk', 'Ed448 OpenSSH fixture is unsupported.');
    const args = ['ed25519', 'ed448'].includes(id) ? ['-t', id] : id === 'dsa' ? ['-t', 'dsa', '-b', '1024'] : id.startsWith('P-') ? ['-t', 'ecdsa', '-b', id.slice(2)] : ['-t', 'rsa', '-b', id.slice(3)];
    if (format === 'openssh' && !['rsa512', 'rsa768', 'dsa'].includes(id)) {
      native('ssh-keygen', ['-q', ...args, ...(variant ? ['-Z', variant] : []), '-N', passphrase, '-C', comment, '-f', path]);
      return { text: readFileSync(path, 'utf8'), passphrase, publicLine: native('ssh-keygen', ['-y', '-P', passphrase, '-f', path]) };
    }
    // PuTTYgen's software RSA 8192 prime search can exceed this helper's 120 s
    // cap. Qualify its PPK writer independently using a native OpenSSH key;
    // do not raise any deadline or fall back inside the application.
    let sourceArgs = args;
    if (id === 'rsa8192') {
      const source = join(directory, 'openssh-source');
      native('ssh-keygen', ['-q', ...args, '-N', '', '-C', comment, '-f', source]);
      sourceArgs = [source];
    }
    native(puttygen, [...sourceArgs, '-C', comment, '--new-passphrase', passwordFile, '--ppk-param', variant ?? 'version=3,kdf=argon2id,memory=65536,passes=3,parallelism=1', '-o', path]);
    if (format === 'openssh') {
      const converted = join(directory, 'openssh');
      native(puttygen, [path, '--old-passphrase', passwordFile, '--new-passphrase', passwordFile, '-O', 'private-openssh-new', '-o', converted]);
      return { text: readFileSync(converted, 'utf8'), passphrase, publicLine: native(puttygen, [converted, '-L', '--old-passphrase', passwordFile]) };
    }
    return { text: readFileSync(path, 'utf8'), passphrase, publicLine: native(puttygen, [path, '-L', '--old-passphrase', passwordFile]) };
  });
}
export function independentSsh1Fixture(encrypted: boolean): { bytes: Uint8Array; passphrase: string; publicLine: string } {
  return disposable(directory => {
    const path = join(directory, 'rsa1'), password = join(directory, 'password'), passphrase = encrypted ? randomBytes(24).toString('base64url') : '';
    writeFileSync(password, `${passphrase}\n`, { mode: 0o600 });
    native(puttygen, ['-t', 'rsa1', '-b', '1024', '-C', 'Independent Próba "comment" \\ @test', '--new-passphrase', password, '-o', path]);
    return { bytes: new Uint8Array(readFileSync(path)), passphrase, publicLine: native(puttygen, [path, '-L', '--old-passphrase', password]) };
  });
}
export function verifyModernRejection(text: string, passphrase: string, reason: 'weak-rsa' | 'dsa'): void {
  disposable(directory => {
    const path = join(directory, 'key'); writeFileSync(path, text, { mode: 0o600 });
    try { execFileSync('ssh-keygen', ['-y', '-P', passphrase, '-f', path], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 120_000 }); }
    catch (error) {
      const stderr = String((error as { stderr?: Buffer }).stderr);
      requireSafe(reason === 'weak-rsa' ? /Invalid key length/.test(stderr) : /unknown or unsupported key type/.test(stderr), 'Unexpected native rejection (details suppressed).');
      return;
    }
    throw new Error('Current OpenSSH unexpectedly accepted a legacy profile.');
  });
}
