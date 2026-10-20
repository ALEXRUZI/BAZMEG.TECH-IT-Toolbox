export type LegacyAlgorithm = 'md5' | 'sha1';
export const legacyAlgorithms: LegacyAlgorithm[] = ['md5', 'sha1'];

export function LegacyWarning({ selectedLegacy, onSwitch, onAcknowledge, buttonClass }: {
  selectedLegacy: LegacyAlgorithm[];
  onSwitch: () => void;
  onAcknowledge: () => void;
  buttonClass: string;
}) {
  return <section aria-label="Legacy algorithm security warning" className="space-y-4 rounded-2xl border border-red-400/50 bg-red-400/10 p-4 text-sm leading-6 text-red-200">
    {selectedLegacy.includes('md5') && <div>
      <h3 className="font-semibold">MD5 is cryptographically insecure</h3>
      <p>MD5 lacks collision resistance and has practical collision attacks: an attacker can construct distinct content with the same MD5 digest. MD5 should not be trusted to establish integrity against deliberate manipulation. It remains useful for legacy compatibility and non-adversarial checksum comparisons.</p>
      <a className="underline focus-visible:outline-2 focus-visible:outline-emerald-400" href="https://www.rfc-editor.org/rfc/rfc6151.html" rel="noreferrer">Read the IETF analysis of MD5 security</a>
    </div>}
    {selectedLegacy.includes('sha1') && <div>
      <h3 className="font-semibold">SHA-1 is cryptographically insecure</h3>
      <p>Practical SHA-1 collision attacks have been demonstrated. SHA-1 lacks collision resistance and should not be used for security-sensitive integrity verification. It remains available for compatibility with existing published checksums.</p>
      <a className="underline focus-visible:outline-2 focus-visible:outline-emerald-400" href="https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html" rel="noreferrer">Read Google's research on SHA-1 collisions</a>
    </div>}
    <div className="flex flex-wrap gap-3">
      <button type="button" className={buttonClass} onClick={onSwitch}>Switch to SHA-256</button>
      <button type="button" className={buttonClass} onClick={onAcknowledge}>I understand the risk</button>
    </div>
  </section>;
}
