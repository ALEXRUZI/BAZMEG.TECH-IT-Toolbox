export type ToolId =
  | 'ssh-key-generator'
  | 'hash-calculator'
  | 'dns'
  | 'csr'
  | 'firewalld'
  | 'ufw'
  | 'nftables'
  | 'chmod'
  | 'cron'
  | 'json'
  | 'data-transfer'
  | 'information-units'
  | 'encoder'
  | 'epoch'
  | 'http-header-check'
  | 'tls-cert'
  | 'mac-address-lookup'
  | 'rdap-whois'
  | 'smtp-banner'
  | 'subnet'
  | 'docker-run-compose'
  | 'text-ascii-art'
  | 'rsync-command-builder'
  | 'scp-sftp-command-builder'
  | 'openssl-cert-command-builder'
  | 'systemd-service-timer-generator'
  | 'ssh-config-generator'
  | 'nginx-reverse-proxy-config-generator'
  | 'text-compare'
  | 'password-secret-generator';

export type Tool = {
  id: ToolId;
  name: string;
  description: string;
  status: 'working' | 'mock' | 'planned';
  category:
    | 'Network'
    | 'Linux'
    | 'Developer'
    | 'General IT'
    | 'Network / DNS / Internet'
    | 'Linux / Admin'
    | 'Security / Certificates'
    | 'Text / Utilities'
    | 'Containers';
  tags: string[];
};
