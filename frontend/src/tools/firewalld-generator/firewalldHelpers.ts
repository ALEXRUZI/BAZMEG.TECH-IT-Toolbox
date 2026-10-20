export function validateZoneName(value: string) {
  const trimmedValue = value.trim();
  if (!trimmedValue) {
    return 'Zone name is required.';
  }
  if (!/^[A-Za-z][A-Za-z0-9_-]*$/.test(trimmedValue)) {
    return 'Zone name must start with a letter and use only letters, numbers, hyphens, or underscores.';
  }
  return null;
}

export const firewalldZones = ['public', 'trusted', 'internal', 'external', 'dmz', 'work', 'home', 'block', 'drop'];

export const commonFirewalldServices = [
  'ssh',
  'http',
  'https',
  'dns',
  'ntp',
  'smtp',
  'smtps',
  'ftp',
  'nfs',
  'samba',
  'iscsi-target',
  'ldap',
  'ldaps',
  'imap',
  'imaps',
  'mysql',
  'postgresql',
  'redis',
  'mongodb',
  'grafana',
  'prometheus',
  'zabbix-agent',
  'zabbix-server',
];
