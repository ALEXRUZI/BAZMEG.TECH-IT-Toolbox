const commonPorts = [
  ['22', 'SSH'],
  ['21', 'FTP'],
  ['990', 'FTPS implicit SSL/TLS'],
  ['25', 'SMTP'],
  ['587', 'SMTPS STARTTLS'],
  ['465', 'SMTPS implicit SSL/TLS'],
  ['53', 'DNS'],
  ['123', 'NTP'],
  ['80', 'HTTP'],
  ['443', 'HTTPS'],
  ['2049', 'NFSv4 data transfer'],
  ['3000', 'Grafana'],
  ['9090', 'Prometheus'],
  ['445', 'SMB/CIFS'],
  ['3260', 'iSCSI target'],
  ['3306', 'MySQL/MariaDB'],
  ['5432', 'PostgreSQL'],
  ['6379', 'Redis'],
  ['27017', 'MongoDB'],
  ['389', 'LDAP'],
  ['636', 'LDAPS'],
  ['143', 'IMAP'],
  ['993', 'IMAPS'],
  ['10050', 'Zabbix agent passive checks'],
  ['10051', 'Zabbix active checks/server trapper'],
];

export function CommonPortsHint({ onSelectPort }: { onSelectPort: (port: string) => void }) {
  return (
    <aside className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
      <h3 className="text-sm font-semibold text-zinc-200">Common destination ports</h3>
      <div className="mt-3 space-y-2 text-sm">
        {commonPorts.map(([port, name]) => (
          <button
            key={`${name}-${port}`}
            className="flex w-full items-center justify-between gap-4 rounded-lg px-2 py-1 text-left text-zinc-400 transition hover:bg-emerald-500/10 hover:text-zinc-100"
            type="button"
            onClick={() => onSelectPort(port)}
          >
            <span>{name}</span>
            <span className="font-mono text-zinc-300">{port}</span>
          </button>
        ))}
      </div>
    </aside>
  );
}
