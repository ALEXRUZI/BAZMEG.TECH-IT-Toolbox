import { PlannedTool } from './layout/PlannedTool';
import { RdapLookup } from '../tools/rdap-whois/RdapLookup';
import { SshKeyGenerator } from '../tools/ssh-key-generator/SshKeyGenerator';
import { HashCalculator } from '../tools/hash-calculator/HashCalculator';
import type { Tool } from './toolTypes';
import { ChmodCalculator } from '../tools/chmod-calculator/ChmodCalculator';
import { CronGenerator } from '../tools/cron-generator/CronGenerator';
import { EpochTool } from '../tools/epoch-converter/EpochTool';
import { CsrGenerator } from '../tools/csr-generator/CsrGenerator';
import { DnsChecker } from '../tools/dns-checker/DnsChecker';
import { HttpHeaderChecker } from '../tools/http-header-checker/HttpHeaderChecker';
import { PasswordSecretGenerator } from '../tools/password-secret-generator/PasswordSecretGenerator';
import { TlsCertificateChecker } from '../tools/tls-certificate-checker/TlsCertificateChecker';
import { FirewallGenerator } from '../tools/ufw-generator/UfwGenerator';
import { NftablesGenerator } from '../tools/nftables-generator/NftablesGenerator';
import { FirewalldGenerator } from '../tools/firewalld-generator/FirewalldGenerator';
import { DataTransferCalculator } from '../tools/data-transfer-calculator/DataTransferCalculator';
import { EncoderTool } from '../tools/base64-url-encoder/EncoderTool';
import { InformationUnitsCalculator } from '../tools/information-units-calculator/InformationUnitsCalculator';
import { JsonYamlFormatter } from '../tools/json-yaml-formatter/JsonYamlFormatter';

export function renderTool(tool: Tool) {
  switch (tool.id) {
    case 'ssh-key-generator':
      return <SshKeyGenerator />;
    case 'hash-calculator':
      return <HashCalculator />;
    case 'csr':
      return <CsrGenerator />;
    case 'ufw':
      return <FirewallGenerator />;
    case 'nftables':
      return <NftablesGenerator />;
    case 'firewalld':
      return <FirewalldGenerator />;
    case 'chmod':
      return <ChmodCalculator />;
    case 'cron':
      return <CronGenerator />;
    case 'json':
      return <JsonYamlFormatter />;
    case 'encoder':
      return <EncoderTool />;
    case 'epoch':
      return <EpochTool />;
    case 'data-transfer':
      return <DataTransferCalculator />;
    case 'information-units':
      return <InformationUnitsCalculator />;
    case 'tls-cert':
      return <TlsCertificateChecker />;
    case 'http-header-check':
      return <HttpHeaderChecker />;
    case 'dns':
      return <DnsChecker />;
    case 'password-secret-generator':
      return <PasswordSecretGenerator />;
    case 'rdap-whois':
      return <RdapLookup />;
    case 'mac-address-lookup':
    case 'smtp-banner':
    case 'subnet':
    case 'docker-run-compose':
    case 'text-ascii-art':
    case 'rsync-command-builder':
    case 'scp-sftp-command-builder':
    case 'openssl-cert-command-builder':
    case 'systemd-service-timer-generator':
    case 'ssh-config-generator':
    case 'nginx-reverse-proxy-config-generator':
    case 'text-compare':
      return <PlannedTool tool={tool} />;
  }
}
