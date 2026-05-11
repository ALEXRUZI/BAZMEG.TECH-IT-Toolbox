import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';

type ToolId =
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
  | 'headers'
  | 'tls-cert'
  | 'rdap-whois'
  | 'redirect'
  | 'smtp-banner'
  | 'subnet';

type Tool = {
  id: ToolId;
  name: string;
  description: string;
  status: 'working' | 'mock' | 'planned';
  category: 'Network' | 'Linux' | 'Developer' | 'General IT';
  tags: string[];
};

const tools: Tool[] = [
  {
    id: 'firewalld',
    name: 'Firewalld generator',
    description: 'Generate firewalld rich-rule commands for RHEL, Oracle Linux, Rocky, Alma.',
    status: 'working',
    category: 'Linux',
    tags: ['firewall', 'firewalld', 'rhel', 'rocky', 'alma', 'oracle linux', 'rich rule', 'port', 'network'],
  },
  {
    id: 'ufw',
    name: 'UFW generator',
    description: 'Generate Uncomplicated Firewall commands.',
    status: 'working',
    category: 'Linux',
    tags: ['firewall', 'ufw', 'ubuntu', 'debian', 'port', 'allow', 'deny', 'network'],
  },
  {
    id: 'nftables',
    name: 'nftables generator',
    description: 'Generate nftables add-rule commands for inet filter tables.',
    status: 'working',
    category: 'Linux',
    tags: ['firewall', 'nftables', 'nft', 'linux', 'packet filter', 'port', 'network'],
  },
  {
    id: 'chmod',
    name: 'chmod calculator',
    description: 'Convert read, write, and execute bits into a numeric chmod command.',
    status: 'working',
    category: 'Linux',
    tags: ['chmod', 'permissions', 'linux', 'unix', 'read', 'write', 'execute', 'octal'],
  },
  {
    id: 'cron',
    name: 'Cron generator',
    description: 'Build crontab schedule lines without memorizing field order.',
    status: 'working',
    category: 'Linux',
    tags: ['cron', 'crontab', 'schedule', 'linux', 'automation', 'job'],
  },
  {
    id: 'epoch',
    name: 'Epoch & Unix timestamp',
    description: 'Convert Unix timestamps and inspect the current local time.',
    status: 'working',
    category: 'Linux',
    tags: ['epoch', 'unix timestamp', 'time', 'date', 'logs', 'conversion'],
  },
  {
    id: 'data-transfer',
    name: 'Data Transfer Calculator',
    description: 'Calculate transfer time, speed, or data size from the other two values.',
    status: 'working',
    category: 'Network',
    tags: ['data transfer', 'bandwidth', 'speed', 'file size', 'time', 'calculator', 'network'],
  },
  {
    id: 'information-units',
    name: 'Units of information calculator',
    description: 'Convert data units and data-rate units using decimal and binary prefixes.',
    status: 'working',
    category: 'General IT',
    tags: ['units', 'bits', 'bytes', 'kilobyte', 'kibibyte', 'conversion', 'data rate'],
  },
  {
    id: 'csr',
    name: 'CSR Generator',
    description: 'Generate a private key, public key, and certificate signing request locally in the browser.',
    status: 'working',
    category: 'General IT',
    tags: ['csr', 'certificate', 'tls', 'ssl', 'private key', 'public key', 'sans', 'x509', 'pki'],
  },
  {
    id: 'encoder',
    name: 'Base64 / URL encode',
    description: 'Encode and decode Base64 or URL-safe text in the browser.',
    status: 'working',
    category: 'Developer',
    tags: ['base64', 'url encode', 'url decode', 'encoding', 'decode', 'developer'],
  },
  {
    id: 'json',
    name: 'JSON/YAML formatter',
    description: 'Format JSON and clean up common YAML snippets in the browser.',
    status: 'working',
    category: 'Developer',
    tags: ['json', 'yaml', 'formatter', 'pretty print', 'developer', 'config'],
  },
  {
    id: 'dns',
    name: 'DNS checker',
    description: 'Run single-provider DNS checks or compare fixed public DNS providers.',
    status: 'working',
    category: 'Network',
    tags: ['dns', 'record', 'a', 'aaaa', 'mx', 'txt', 'ns', 'soa', 'caa', 'ptr', 'srv', 'cname', 'lookup', 'domain'],
  },
  {
    id: 'headers',
    name: 'HTTP headers',
    description: 'Inspect response headers through backend proxy later.',
    status: 'planned',
    category: 'Network',
    tags: ['http', 'headers', 'response', 'server', 'web', 'proxy'],
  },
  {
    id: 'tls-cert',
    name: 'TLS cert checker',
    description: 'Inspect certificate issuer, SANs, validity dates, and TLS endpoint details.',
    status: 'working',
    category: 'Network',
    tags: ['tls', 'ssl', 'certificate', 'cert', 'chain', 'issuer', 'sans', 'expiry', 'x509'],
  },
  {
    id: 'rdap-whois',
    name: 'RDAP / WHOIS lookup',
    description: 'Look up domain, IP, and ASN registration records through backend resolver later.',
    status: 'planned',
    category: 'Network',
    tags: ['rdap', 'whois', 'domain', 'ip', 'asn', 'registrar', 'registry', 'lookup'],
  },
  {
    id: 'redirect',
    name: 'Redirect checker',
    description: 'Trace HTTP redirect chains, status codes, and final URLs through backend proxy later.',
    status: 'planned',
    category: 'Network',
    tags: ['redirect', 'http', 'status code', '301', '302', 'url', 'web', 'chain'],
  },
  {
    id: 'smtp-banner',
    name: 'SMTP banner checker',
    description: 'Check SMTP greeting banners and basic mail-server reachability through backend service later.',
    status: 'planned',
    category: 'Network',
    tags: ['smtp', 'mail', 'email', 'banner', 'mx', 'server', 'port 25'],
  },
  {
    id: 'subnet',
    name: 'Subnet calculator',
    description: 'CIDR helper for quick subnet planning.',
    status: 'planned',
    category: 'Network',
    tags: ['subnet', 'cidr', 'ip', 'ipv4', 'network', 'mask', 'calculator'],
  },
];

const statusStyle: Record<Tool['status'], string> = {
  working: 'bg-emerald-500/10 text-emerald-300 ring-emerald-400/30',
  mock: 'bg-amber-400/10 text-amber-300 ring-amber-400/20',
  planned: 'bg-yellow-400/10 text-yellow-300 ring-yellow-400/25',
};

function App() {
  const [selectedToolId, setSelectedToolId] = useState<ToolId | null>(null);
  const selectedTool = tools.find((tool) => tool.id === selectedToolId) ?? null;

  return (
    <main className="min-h-screen bg-zinc-950 text-zinc-100">
      <div className="mx-auto flex max-w-[1600px] flex-col gap-8 px-4 py-6 sm:px-6 lg:px-10 2xl:px-12">
        <Header />
        <Hero />
        <section className="grid gap-6 lg:grid-cols-[360px_minmax(0,1fr)]">
          <ToolList selectedToolId={selectedToolId} onSelect={setSelectedToolId} />
          <Workbench selectedTool={selectedTool} />
        </section>
      </div>
      <BackToTopButton />
    </main>
  );
}

function BackToTopButton() {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const updateVisibility = () => setIsVisible(window.scrollY > 500);

    updateVisibility();
    window.addEventListener('scroll', updateVisibility, { passive: true });

    return () => window.removeEventListener('scroll', updateVisibility);
  }, []);

  if (!isVisible) {
    return null;
  }

  return (
    <button
      className="fixed bottom-5 right-5 z-40 rounded-full border border-emerald-500/35 bg-zinc-950/90 px-4 py-2 text-sm font-semibold text-emerald-200 shadow-xl shadow-black/40 backdrop-blur transition hover:border-emerald-400 hover:bg-emerald-500/15"
      type="button"
      onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
    >
      Back to top
    </button>
  );
}

function Header() {
  return (
    <header className="flex flex-col gap-4 border-b border-white/10 pb-5 md:flex-row md:items-center md:justify-between">
      <div className="flex items-center gap-4">
        <ToolboxIcon />
        <div>
          <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">
            IT Toolbox |{' '}
            <span className="text-green-400 drop-shadow-[0_0_10px_rgba(74,222,128,0.35)]">Bazmeg.Tech</span>
          </h1>
        </div>
      </div>
    </header>
  );
}

function ToolboxIcon() {
  return (
    <div className="flex size-16 shrink-0 items-center justify-center rounded-2xl border border-green-400/35 bg-emerald-500/10 shadow-lg shadow-green-950/40">
      <svg
        aria-hidden="true"
        className="size-10 text-green-400 drop-shadow-[0_0_12px_rgba(74,222,128,0.45)]"
        viewBox="0 0 64 64"
      >
        <path
          d="M23 18v-3.5A4.5 4.5 0 0 1 27.5 10h9A4.5 4.5 0 0 1 41 14.5V18"
          fill="none"
          stroke="currentColor"
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth="4"
        />
        <path
          d="M12 22h40a5 5 0 0 1 5 5v22a5 5 0 0 1-5 5H12a5 5 0 0 1-5-5V27a5 5 0 0 1 5-5Z"
          fill="currentColor"
          opacity="0.18"
        />
        <path
          d="M12 22h40a5 5 0 0 1 5 5v22a5 5 0 0 1-5 5H12a5 5 0 0 1-5-5V27a5 5 0 0 1 5-5Z"
          fill="none"
          stroke="currentColor"
          strokeLinejoin="round"
          strokeWidth="4"
        />
        <path d="M7 34h50" fill="none" stroke="currentColor" strokeLinecap="round" strokeWidth="4" />
        <path
          d="M27 31h10v8H27z"
          fill="#22c55e"
          stroke="currentColor"
          strokeLinejoin="round"
          strokeWidth="3"
        />
      </svg>
    </div>
  );
}

function Hero() {
  return (
    <section className="relative overflow-hidden rounded-3xl border border-green-400/35 bg-gradient-to-br from-green-900/80 via-emerald-950 to-zinc-950 p-6 shadow-2xl shadow-green-950/50 sm:p-8">
      <a
        className="absolute right-4 top-4 inline-flex size-12 items-center justify-center rounded-2xl border border-emerald-400/35 bg-zinc-950/45 text-emerald-200 transition hover:border-emerald-300 hover:bg-emerald-500/15 sm:right-6 sm:top-6 sm:size-14"
        href="https://github.com/ALEXRUZI/BAZMEG.TECH-IT-Toolbox"
        target="_blank"
        rel="noreferrer"
        aria-label="GitHub project"
        title="GitHub project"
      >
        <svg aria-hidden="true" className="size-7 sm:size-8" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 2C6.48 2 2 6.58 2 12.22c0 4.5 2.87 8.32 6.84 9.67.5.09.68-.22.68-.49v-1.9c-2.78.62-3.37-1.22-3.37-1.22-.45-1.18-1.11-1.49-1.11-1.49-.91-.64.07-.63.07-.63 1 .07 1.53 1.06 1.53 1.06.9 1.56 2.35 1.11 2.92.85.09-.66.35-1.11.63-1.37-2.22-.26-4.56-1.14-4.56-5.06 0-1.12.39-2.03 1.03-2.75-.1-.26-.45-1.3.1-2.71 0 0 .84-.28 2.75 1.05A9.28 9.28 0 0 1 12 6.9c.85 0 1.7.12 2.5.34 1.9-1.33 2.74-1.05 2.74-1.05.55 1.41.2 2.45.1 2.71.64.72 1.03 1.63 1.03 2.75 0 3.93-2.34 4.8-4.57 5.05.36.32.68.94.68 1.9v2.8c0 .27.18.59.69.49A10.1 10.1 0 0 0 22 12.22C22 6.58 17.52 2 12 2Z" />
        </svg>
      </a>
      <div>
        <div>
          <div className="mt-3 max-w-5xl pr-14 sm:pr-20">
            <h2 className="max-w-3xl text-3xl font-bold tracking-tight sm:text-5xl">
              Useful sysadmin tools for real infrastructure work.
            </h2>
          </div>
          <p className="mt-4 max-w-2xl text-base leading-7 text-zinc-300">
            Generate firewall rules, cron schedules, permissions, and other admin snippets with validation built in before
            you paste anything into a terminal.
          </p>
        </div>
      </div>
    </section>
  );
}

function ToolList({
  selectedToolId,
  onSelect,
}: {
  selectedToolId: ToolId | null;
  onSelect: (toolId: ToolId) => void;
}) {
  const [searchQuery, setSearchQuery] = useState('');
  const normalizedSearchQuery = searchQuery.trim().toLowerCase();
  const visibleTools = normalizedSearchQuery
    ? tools.filter((tool) => getToolSearchText(tool).includes(normalizedSearchQuery))
    : tools;

  return (
    <aside className="rounded-3xl border border-emerald-500/15 bg-zinc-900/70 p-4">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-lg font-semibold">Tools</h2>
        <span className="rounded-full bg-emerald-500/10 px-2.5 py-1 text-xs font-semibold text-emerald-300">
          {visibleTools.length}
        </span>
      </div>
      <div className="mb-4 grid gap-2 sm:grid-cols-[1fr_auto]">
        <input
          className={inputClass()}
          placeholder="Search tools, tags, ports..."
          value={searchQuery}
          onChange={(event) => setSearchQuery(event.target.value)}
        />
        <button
          className="rounded-xl border border-emerald-500/30 px-4 py-2 text-sm font-semibold text-emerald-300 transition hover:border-emerald-400 hover:bg-emerald-500/10 disabled:cursor-not-allowed disabled:opacity-50"
          type="button"
          onClick={() => setSearchQuery('')}
          disabled={!searchQuery}
        >
          {searchQuery ? 'Clear' : 'Search'}
        </button>
      </div>
      <div className="space-y-3">
        {visibleTools.map((tool) => {
          const isSelected = tool.id === selectedToolId;

          return (
            <button
              key={tool.id}
              className={`group relative w-full overflow-hidden rounded-2xl border p-4 text-left transition duration-200 ${
                isSelected
                  ? 'border-emerald-400/50 bg-emerald-950/30'
                  : 'border-white/10 bg-zinc-950/60 hover:-translate-y-1 hover:border-emerald-400/45 hover:bg-emerald-950/20 hover:shadow-lg hover:shadow-emerald-950/40'
              }`}
              type="button"
              onClick={() => onSelect(tool.id)}
            >
              {!isSelected && (
                <span className="pointer-events-none absolute inset-y-3 left-0 w-1 rounded-r-full bg-green-400 opacity-0 shadow-[0_0_16px_rgba(74,222,128,0.8)] transition-opacity duration-200 group-hover:opacity-100" />
              )}
              <div className="relative flex items-start justify-between gap-3">
                <div>
                  <h3 className={`font-semibold ${tool.status === 'planned' ? 'text-yellow-300' : ''}`}>
                    {tool.name}
                  </h3>
                  <p
                    className={`mt-1 text-xs font-semibold uppercase tracking-[0.2em] ${
                      tool.status === 'planned'
                        ? 'text-yellow-200/80'
                        : 'text-green-400 drop-shadow-[0_0_10px_rgba(74,222,128,0.35)]'
                    }`}
                  >
                    {tool.category}
                  </p>
                </div>
                <span className={`rounded-full px-2 py-1 text-xs ring-1 ${statusStyle[tool.status]}`}>
                  {tool.status}
                </span>
              </div>
              <p
                className={`relative mt-3 text-sm leading-6 ${
                  tool.status === 'planned' ? 'text-yellow-100/80' : 'text-zinc-300'
                }`}
              >
                {tool.description}
              </p>
            </button>
          );
        })}
        {!visibleTools.length && (
          <div className="rounded-2xl border border-dashed border-emerald-500/25 bg-zinc-950/60 p-4 text-sm leading-6 text-zinc-400">
            No tools match that search.
          </div>
        )}
      </div>
    </aside>
  );
}

function getToolSearchText(tool: Tool) {
  return [tool.name, tool.description, tool.status, tool.category, ...tool.tags].join(' ').toLowerCase();
}

function Workbench({ selectedTool }: { selectedTool: Tool | null }) {
  if (!selectedTool) {
    return <EmptyWorkbench />;
  }

  return <section className="min-w-0">{renderTool(selectedTool)}</section>;
}

function renderTool(tool: Tool) {
  switch (tool.id) {
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
    case 'dns':
      return <DnsChecker />;
    case 'headers':
    case 'rdap-whois':
    case 'redirect':
    case 'smtp-banner':
    case 'subnet':
      return <PlannedTool tool={tool} />;
  }
}

function EmptyWorkbench() {
  return (
    <Panel title="Choose a tool">
      <div className="rounded-2xl border border-dashed border-emerald-500/25 bg-zinc-950/60 p-8 text-center text-zinc-100">
        <p className="text-lg font-semibold">Select a tool from the list.</p>
        <p className="mt-2 text-sm leading-6 text-zinc-400">
          The selected tool will load here.
        </p>
      </div>
    </Panel>
  );
}

function PlannedTool({ tool }: { tool: Tool }) {
  return (
    <Panel title={tool.name}>
      <div className="rounded-2xl border border-amber-400/20 bg-amber-400/10 p-4 text-sm leading-6 text-amber-100">
        {tool.description} This UI is planned for a later version.
      </div>
    </Panel>
  );
}

type TlsCheckStatus = 'pass' | 'warn' | 'fail';

type TlsCertificateDetail = {
  type: 'server' | 'intermediate' | 'root' | 'chain';
  subject: Record<string, string | undefined>;
  issuer: Record<string, string | undefined>;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  serialNumber: string | null;
  fingerprint256: string | null;
  subjectAltName: string | null;
  signatureAlgorithm: string | null;
  publicKeyAlgorithm: string | null;
  modulusLength: number | null;
  bits: number | null;
};

type TlsCheckSuccess = {
  ok: true;
  host: string;
  port: number;
  resolvedAddresses: string[];
  tls: {
    authorized: boolean;
    authorizationError: string | null;
    protocol: string | null;
    cipher: string | null;
  };
  certificate: TlsCertificateDetail;
  warnings: string[];
  summary: {
    resolves: boolean;
    trusted: boolean;
    hostnameMatches: boolean;
    notExpired: boolean;
    chainProvided: boolean;
  };
  checks: Array<{
    id: string;
    status: TlsCheckStatus;
    message: string;
  }>;
  chain: TlsCertificateDetail[];
};

type TlsCheckErrorResponse = {
  ok: false;
  error: {
    code: string;
    message: string;
  };
};

type TlsCheckResponse = TlsCheckSuccess | TlsCheckErrorResponse;

const tlsPortOptions = [
  { value: 443, label: '443 - HTTPS' },
  { value: 4443, label: '4443 - HTTPS alternate' },
  { value: 7443, label: '7443 - HTTPS alternate' },
  { value: 8443, label: '8443 - HTTPS alternate' },
  { value: 9443, label: '9443 - HTTPS alternate' },
  { value: 10443, label: '10443 - HTTPS alternate / appliance HTTPS' },
] as const;

function TlsCertificateChecker() {
  const tlsHostExample = 'google.com';
  const [hostInput, setHostInput] = useState('');
  const [selectedPort, setSelectedPort] = useState(443);
  const [isHostFocused, setIsHostFocused] = useState(false);
  const [result, setResult] = useState<TlsCheckSuccess | null>(null);
  const [error, setError] = useState<TlsCheckErrorResponse['error'] | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const hasHost = hostInput.trim().length > 0;

  async function checkCertificate() {
    const normalizedHost = normalizeTlsHostInput(hostInput);

    setHostInput(normalizedHost);
    setIsLoading(true);
    setResult(null);
    setError(null);

    try {
      const response = await fetch('/api/tools/tls-check', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          host: normalizedHost,
          port: selectedPort,
        }),
      });
      const body = (await response.json()) as TlsCheckResponse;

      if (!response.ok || !body.ok) {
        setError(body.ok ? {
          code: 'TLS_CHECK_FAILED',
          message: 'Certificate check failed.',
        } : body.error);
        return;
      }

      setResult(body);
    } catch {
      setError({
        code: 'TLS_CHECK_FAILED',
        message: 'Certificate check failed.',
      });
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <Panel title="TLS/SSL certificate checker">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Check the public certificate and TLS settings for an HTTPS endpoint.
      </p>
      <div className="mt-5 grid gap-4 md:grid-cols-[minmax(0,1fr)_260px_auto]">
        <Field>
          <Label>Hostname</Label>
          <div className="relative">
            {!hostInput && !isHostFocused && (
              <span className="pointer-events-none absolute inset-y-0 left-3 flex items-center text-sm text-zinc-500">
                {tlsHostExample}
              </span>
            )}
            <input
              aria-label="Hostname"
              className={inputClass()}
              value={hostInput}
              onBlur={() => {
                setIsHostFocused(false);
                setHostInput((value) => normalizeTlsHostInput(value));
              }}
              onChange={(event) => setHostInput(event.target.value)}
              onFocus={() => setIsHostFocused(true)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && hasHost && !isLoading) {
                  void checkCertificate();
                }
              }}
            />
          </div>
        </Field>
        <Field>
          <Label>Port</Label>
          <select
            className={inputClass()}
            value={selectedPort}
            onChange={(event) => setSelectedPort(Number(event.target.value))}
          >
            {tlsPortOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          <p className="text-xs leading-5 text-zinc-400">Only common direct-TLS HTTPS ports are supported.</p>
        </Field>
        <div className="flex items-end">
          <button
            className="w-full rounded-xl border border-emerald-500/35 bg-emerald-500 px-5 py-2 text-sm font-semibold text-zinc-950 transition hover:border-emerald-300 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:border-zinc-700 disabled:bg-zinc-800 disabled:text-zinc-500 md:w-auto"
            type="button"
            onClick={() => void checkCertificate()}
            disabled={!hasHost || isLoading}
            aria-busy={isLoading}
          >
            {isLoading ? 'Checking...' : 'Check certificate'}
          </button>
        </div>
      </div>

      {error && (
        <div className="mt-5 rounded-2xl border border-red-300/35 bg-red-950/40 p-4">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-red-200">Error code</p>
          <p className="mt-1 font-mono text-sm text-red-100">{error.code}</p>
          <p className="mt-4 text-xs font-semibold uppercase tracking-[0.16em] text-red-200">Message</p>
          <p className="mt-1 text-sm leading-6 text-red-50">{error.message}</p>
        </div>
      )}

      {result && (
        <div className="mt-6 space-y-5">
          <TlsResultSection title="Result summary">
            <div className="space-y-3">
              {result.checks.map((check) => (
                <TlsCheckRow key={check.id} check={check} />
              ))}
            </div>
          </TlsResultSection>

          <TlsResultSection title="TLS status">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              <ResultItem label="Host" value={result.host} />
              <ResultItem label="Port" value={String(result.port)} />
              <ResultItem label="Authorized" value={result.tls.authorized ? 'Yes' : 'No'} />
              <ResultItem label="Authorization error" value={result.tls.authorizationError} />
              <ResultItem label="Protocol" value={result.tls.protocol} />
              <ResultItem label="Cipher" value={result.tls.cipher} />
            </div>
          </TlsResultSection>

          <TlsResultSection title="DNS resolution">
            <TlsListBlock values={result.resolvedAddresses} />
          </TlsResultSection>

          <TlsResultSection title="Server certificate">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              <ResultItem label="Subject CN" value={result.certificate.subject.CN} />
              <ResultItem label="Issuer CN" value={result.certificate.issuer.CN} />
              <ResultItem label="Issuer O" value={result.certificate.issuer.O} />
              <ResultItem label="Valid from" value={result.certificate.validFrom} />
              <ResultItem label="Valid to" value={result.certificate.validTo} />
              <ResultItem label="Days remaining" value={formatOptionalNumber(result.certificate.daysRemaining)} />
              <ResultItem label="Serial number" value={result.certificate.serialNumber} />
              <ResultItem label="SHA256 fingerprint" value={result.certificate.fingerprint256} />
            </div>
            <div className="mt-3">
              <TlsListBlock values={parseSubjectAltNames(result.certificate.subjectAltName)} fallback={result.certificate.subjectAltName} />
            </div>
          </TlsResultSection>

          <TlsCertificateChain chain={result.chain} />

          {result.warnings.length > 0 && (
            <TlsResultSection title="Warnings">
              <TlsListBlock values={result.warnings} />
            </TlsResultSection>
          )}
        </div>
      )}
    </Panel>
  );
}

function TlsResultSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="min-w-0 max-w-full rounded-2xl border border-emerald-500/15 bg-zinc-900/70 p-4">
      <h3 className="text-sm font-semibold uppercase tracking-[0.16em] text-emerald-200">{title}</h3>
      <div className="mt-4 min-w-0">{children}</div>
    </section>
  );
}

function TlsCheckRow({ check }: { check: { status: TlsCheckStatus; message: string } }) {
  const statusCopy = {
    pass: { icon: '✓', label: 'Pass', className: 'border-emerald-400/35 bg-emerald-500/10 text-emerald-200' },
    warn: { icon: '!', label: 'Warn', className: 'border-amber-300/35 bg-amber-400/10 text-amber-100' },
    fail: { icon: '×', label: 'Fail', className: 'border-red-300/35 bg-red-500/10 text-red-100' },
  }[check.status];

  return (
    <div className={`flex items-start gap-3 rounded-xl border p-3 ${statusCopy.className}`}>
      <span className="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full border border-current text-sm font-bold">
        {statusCopy.icon}
      </span>
      <div>
        <p className="text-xs font-semibold uppercase tracking-[0.16em]">{statusCopy.label}</p>
        <p className="mt-1 text-sm leading-6">{check.message}</p>
      </div>
    </div>
  );
}

function TlsCertificateChain({ chain }: { chain: TlsCertificateDetail[] }) {
  if (chain.length === 0) {
    return null;
  }

  return (
    <TlsResultSection title="Certificate chain">
      <div className="space-y-3">
        {chain.map((certificate, index) => (
          <div key={`${certificate.fingerprint256 || certificate.serialNumber || index}-${index}`}>
            <TlsCertificateCard certificate={certificate} index={index} />
            {index < chain.length - 1 && (
              <div className="flex justify-center py-2 text-emerald-300/70" aria-hidden="true">
                ↓
              </div>
            )}
          </div>
        ))}
      </div>
    </TlsResultSection>
  );
}

function TlsCertificateCard({ certificate, index }: { certificate: TlsCertificateDetail; index: number }) {
  const title = index === 0 ? 'Server certificate' : getChainCertificateTitle(certificate, index);
  const keyDetails = [
    certificate.publicKeyAlgorithm,
    certificate.bits ? `${certificate.bits} bits` : null,
    certificate.modulusLength ? `${certificate.modulusLength} modulus bits` : null,
  ].filter(Boolean).join(' / ');

  return (
    <article className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h4 className="text-base font-semibold text-zinc-100">{title}</h4>
          <p className="mt-1 text-sm text-zinc-400">{certificate.subject.CN || 'Subject CN unavailable'}</p>
        </div>
        <span className="rounded-full border border-emerald-400/25 bg-emerald-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.14em] text-emerald-200">
          {certificate.type}
        </span>
      </div>
      <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        <ResultItem label="Subject CN" value={certificate.subject.CN} />
        <ResultItem label="Issuer CN" value={certificate.issuer.CN} />
        <ResultItem label="Issuer O" value={certificate.issuer.O} />
        <ResultItem label="Valid from" value={certificate.validFrom} />
        <ResultItem label="Valid to" value={certificate.validTo} />
        <ResultItem label="Days remaining" value={formatOptionalNumber(certificate.daysRemaining)} />
        <ResultItem label="Serial number" value={certificate.serialNumber} />
        <ResultItem label="Signature algorithm" value={certificate.signatureAlgorithm} />
        <ResultItem label="Public key" value={keyDetails || null} />
      </div>
      <div className="mt-3 grid gap-3 lg:grid-cols-2">
        <ResultBlock label="SHA256 fingerprint" value={certificate.fingerprint256} />
        <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500">Subject Alternative Names</p>
          <div className="mt-3">
            <TlsListBlock values={parseSubjectAltNames(certificate.subjectAltName)} fallback={certificate.subjectAltName} />
          </div>
        </div>
      </div>
    </article>
  );
}

function getChainCertificateTitle(certificate: TlsCertificateDetail, index: number) {
  if (certificate.type === 'root') {
    return 'Root certificate';
  }

  if (certificate.type === 'intermediate') {
    return 'Intermediate certificate';
  }

  return `Chain certificate ${index + 1}`;
}

function TlsListBlock({ values, fallback }: { values: string[]; fallback?: string | null }) {
  const displayValues = values.length > 0 ? values : fallback ? [fallback] : [];

  if (displayValues.length === 0) {
    return <p className="text-sm text-zinc-400">-</p>;
  }

  return (
    <details className="rounded-xl border border-white/10 bg-zinc-950/60 p-4" open={displayValues.length <= 8}>
      <summary className="cursor-pointer text-sm font-semibold text-zinc-200">
        {displayValues.length} {displayValues.length === 1 ? 'item' : 'items'}
      </summary>
      <div className="mt-3 max-h-64 space-y-2 overflow-auto pr-2">
        {displayValues.map((value, index) => (
          <div
            key={`${value}-${index}`}
            className="break-words rounded-lg border border-white/10 bg-zinc-950 px-3 py-2 font-mono text-xs leading-5 text-zinc-100"
          >
            {value}
          </div>
        ))}
      </div>
    </details>
  );
}

function normalizeTlsHostInput(value: string): string {
  const trimmed = value.trim();

  if (!trimmed) {
    return '';
  }

  try {
    const withScheme = /^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`;
    const parsed = new URL(withScheme);

    return parsed.hostname.toLowerCase();
  } catch {
    return trimmed
      .replace(/^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//, '')
      .split(/[/?#]/)[0]
      .trim()
      .toLowerCase();
  }
}

function ResultItem({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div className="min-w-0 rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500">{label}</p>
      <p className="mt-2 break-words font-mono text-sm text-zinc-100 [overflow-wrap:anywhere]">{value || '-'}</p>
    </div>
  );
}

function ResultBlock({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div className="min-w-0 rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500">{label}</p>
      <pre className="mt-2 whitespace-pre-wrap break-words font-mono text-sm leading-6 text-zinc-100 [overflow-wrap:anywhere]">
        {value || '-'}
      </pre>
    </div>
  );
}

function formatOptionalNumber(value: number | null) {
  return value === null ? null : String(value);
}

function formatDistinguishedName(value: Record<string, string | undefined>) {
  const entries = Object.entries(value).filter(([, entryValue]) => entryValue);

  return entries.length > 0 ? entries.map(([key, entryValue]) => `${key}: ${entryValue}`).join('\n') : null;
}

function parseSubjectAltNames(value: string | null) {
  if (!value) {
    return [];
  }

  return value
    .split(/,\s*/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <article className="min-w-0 max-w-full rounded-3xl border border-emerald-500/15 bg-zinc-900/70 p-5 text-zinc-100 shadow-xl shadow-black/30">
      <h2 className="text-xl font-semibold text-white">{title}</h2>
      <div className="mt-5 min-w-0">{children}</div>
    </article>
  );
}

function Label({ children }: { children: ReactNode }) {
  return <label className="text-sm font-medium text-zinc-300">{children}</label>;
}

function Field({ children }: { children: ReactNode }) {
  return <div className="space-y-2">{children}</div>;
}

function HelpTooltip({ text }: { text: string }) {
  return (
    <span className="group relative inline-flex">
      <span className="inline-flex size-5 items-center justify-center rounded-full border border-white/15 bg-zinc-950 text-xs font-bold text-zinc-400">
        ?
      </span>
      <span className="pointer-events-none absolute bottom-full left-1/2 z-10 mb-2 w-64 -translate-x-1/2 rounded-xl border border-white/10 bg-zinc-950 p-3 text-xs font-normal leading-5 text-zinc-300 opacity-0 shadow-xl shadow-black/30 transition group-hover:opacity-100">
        {text}
      </span>
    </span>
  );
}

function inputClass(hasError = false, isMuted = false) {
  const borderClass = hasError ? 'border-red-400/60 focus:border-red-400' : 'border-white/10 focus:border-emerald-500';
  const textClass = isMuted ? 'text-zinc-400' : 'text-zinc-100';

  return `w-full rounded-xl border ${borderClass} bg-zinc-950 px-3 py-2 text-sm ${textClass} outline-none transition`;
}

function ExampleTextInput({
  value,
  example,
  hasError = false,
  onChange,
}: {
  value: string;
  example: string;
  hasError?: boolean;
  onChange: (value: string) => void;
}) {
  const [isFocused, setIsFocused] = useState(false);
  const isShowingExample = !isFocused && !value;

  return (
    <input
      className={inputClass(hasError, isShowingExample)}
      value={isShowingExample ? example : value}
      onFocus={() => setIsFocused(true)}
      onChange={(event) => onChange(event.target.value)}
      onBlur={() => setIsFocused(false)}
    />
  );
}

function validateIpv4Cidr(value: string) {
  const trimmedValue = value.trim();

  if (!trimmedValue) {
    return 'Source is required.';
  }

  const [ip, prefix, extra] = trimmedValue.split('/');

  if (extra !== undefined) {
    return 'Use only one CIDR prefix, for example 10.10.190.14/32.';
  }

  if (prefix !== undefined) {
    if (!/^\d+$/.test(prefix)) {
      return 'CIDR prefix must be a number from 0 to 32.';
    }

    const prefixNumber = Number(prefix);

    if (prefixNumber < 0 || prefixNumber > 32) {
      return 'CIDR prefix must be between 0 and 32.';
    }
  }

  const octets = ip.split('.');

  if (octets.length !== 4) {
    return 'IPv4 address must have 4 octets.';
  }

  const hasInvalidOctet = octets.some((octet) => {
    if (!/^\d+$/.test(octet)) {
      return true;
    }

    const octetNumber = Number(octet);

    return octetNumber < 0 || octetNumber > 255;
  });

  if (hasInvalidOctet) {
    return 'Each IPv4 octet must be a number from 0 to 255.';
  }

  return null;
}

function validatePort(value: string) {
  const trimmedValue = value.trim();

  if (!trimmedValue) {
    return 'Port is required.';
  }

  if (!/^\d+$/.test(trimmedValue)) {
    return 'Port must be a number.';
  }

  const portNumber = Number(trimmedValue);

  if (portNumber < 1 || portNumber > 65535) {
    return 'Port must be between 1 and 65535.';
  }

  return null;
}

function validateZoneName(value: string) {
  const trimmedValue = value.trim();

  if (!trimmedValue) {
    return 'Zone name is required.';
  }

  if (!/^[A-Za-z][A-Za-z0-9_-]*$/.test(trimmedValue)) {
    return 'Zone name must start with a letter and use only letters, numbers, hyphens, or underscores.';
  }

  return null;
}

function CommandBlock({ children, scrollInside = false }: { children: string; scrollInside?: boolean }) {
  const [copied, setCopied] = useState(false);
  const preClassName = scrollInside
    ? 'max-h-[70vh] overflow-auto p-4 text-sm text-zinc-100'
    : 'overflow-x-auto p-4 text-sm text-zinc-100';

  async function copyCommand() {
    await navigator.clipboard.writeText(children);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1400);
  }

  return (
    <div className="mt-4 max-w-full overflow-hidden rounded-2xl bg-zinc-950">
      <div className="flex items-center justify-end border-b border-white/10 px-3 py-2">
        <button
          className="rounded-lg border border-emerald-500/30 px-3 py-1 text-xs font-semibold text-emerald-300 transition hover:border-emerald-400 hover:bg-emerald-500/10"
          type="button"
          onClick={copyCommand}
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className={preClassName}>{children}</pre>
    </div>
  );
}

const firewallExamples = {
  source: '10.20.30.40/32',
  sourcePort: '2049',
  destination: '10.20.30.40/32',
  destinationPort: '2049',
};

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

const firewalldZones = ['public', 'trusted', 'internal', 'external', 'dmz', 'work', 'home', 'block', 'drop'];

const commonFirewalldServices = [
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

function clearExampleValue(value: string, example: string, setValue: (nextValue: string) => void) {
  if (value === example) {
    setValue('');
  }
}

function restoreExampleValue(value: string, example: string, setValue: (nextValue: string) => void) {
  if (!value.trim()) {
    setValue(example);
  }
}

function CommonPortsHint({ onSelectPort }: { onSelectPort: (port: string) => void }) {
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

type DnsMode = 'single' | 'burst';
type DnsRecordType = 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' | 'NS' | 'SOA' | 'CAA' | 'PTR' | 'SRV';
type DnsResponseView = 'simple' | 'advanced' | 'raw';
type DnsTxtHelper = 'normal' | 'spf' | 'dkim' | 'dmarc' | 'acme';

type DnsProviderSummary = {
  id: string;
  name: string;
  profile?: string;
  category?: string;
};

type DnsRecord = {
  name: string;
  type: string;
  ttl?: number;
  address?: string;
  target?: string;
  host?: string;
  value?: string;
  chunks?: string[];
  preference?: number;
  exchange?: string;
  resolvedA?: string[];
  resolvedAAAA?: string[];
  priority?: number;
  weight?: number;
  port?: number;
  flags?: number;
  tag?: string;
  [key: string]: unknown;
};

type DnsQuery = {
  input: string;
  queryName: string;
  displayName: string;
  recordType: DnsRecordType;
  service: string | null;
  protocol: string | null;
  domain: string | null;
};

type DnsDiagnostic = {
  id: string;
  status?: string;
  message?: string;
  [key: string]: unknown;
};

type DnsSpfMechanism = {
  token: string;
  qualifier?: string | null;
  result?: string | null;
  mechanism?: string | null;
  value?: string | null;
  prefix?: string | null;
  modifier?: boolean;
  valid?: boolean;
  [key: string]: unknown;
};

type DnsCacheMetadata = {
  fromCache: boolean;
  cacheScope: 'site';
  cacheTtlSeconds?: number;
  cacheAgeSeconds?: number;
  cacheExpiresInSeconds?: number;
};

type DnsProviderResult = {
  ok: boolean;
  mode: DnsMode;
  query: DnsQuery;
  resolver: DnsProviderSummary;
  provider: DnsProviderSummary;
  responseCode: string | null;
  durationMs: number;
  status: string;
  records: DnsRecord[];
  answer: DnsRecord[];
  authority: DnsRecord[];
  additional: DnsRecord[];
  diagnostics: DnsDiagnostic[];
  warnings: string[];
  dnssec: Record<string, unknown>;
  raw: Record<string, unknown>;
};

type DnsCheckSuccess = DnsProviderResult & {
  ok: true;
  cache: DnsCacheMetadata;
  resolver: DnsProviderSummary | {
    group: string;
    providers: DnsProviderSummary[];
  };
  provider: DnsProviderSummary | null;
  providers?: DnsProviderResult[];
};

type DnsCheckErrorResponse = {
  ok: false;
  error: {
    code: string;
    message: string;
  };
};

type DnsCheckResponse = DnsCheckSuccess | DnsCheckErrorResponse;

const dnsRecordTypes: DnsRecordType[] = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'PTR', 'SRV'];

const dnsSingleResolvers: DnsProviderSummary[] = [
  { id: 'cloudflare', name: 'Cloudflare DNS' },
  { id: 'google', name: 'Google DNS' },
  { id: 'opendns', name: 'OpenDNS / Cisco' },
  { id: 'quad9', name: 'Quad9' },
  { id: 'fortiguard', name: 'FortiGuard DNS' },
  { id: 'adguard', name: 'AdGuard DNS' },
  { id: 'verisign', name: 'Verisign Public DNS' },
  { id: 'dnswatch', name: 'DNS.WATCH' },
  { id: 'comodo', name: 'Comodo Secure DNS' },
  { id: 'level3', name: 'Level3 / Lumen' },
  { id: 'neustar', name: 'Neustar UltraDNS' },
];

const dnsStatusLabels: Record<string, string> = {
  ok: 'OK',
  'different-answer': 'Different answer',
  'no-record': 'No record',
  nxdomain: 'NXDOMAIN',
  servfail: 'SERVFAIL',
  refused: 'REFUSED',
  timeout: 'Timeout',
  'possible-filtering': 'Possible filtering',
  'possible-sinkhole': 'Possible sinkhole',
  'possible-dnssec-failure': 'Possible DNSSEC issue',
  'resolver-error': 'Resolver error',
};

const dnsTxtHelperLabels: Record<DnsTxtHelper, string> = {
  normal: 'Normal TXT',
  spf: 'SPF',
  dkim: 'DKIM',
  dmarc: 'DMARC',
  acme: 'ACME challenge',
};

function DnsChecker() {
  const [mode, setMode] = useState<DnsMode>('single');
  const [recordType, setRecordType] = useState<DnsRecordType>('A');
  const [resolverId, setResolverId] = useState('cloudflare');
  const [queryInput, setQueryInput] = useState('');
  const [txtHelper, setTxtHelper] = useState<DnsTxtHelper>('normal');
  const [dkimSelector, setDkimSelector] = useState('');
  const [srvService, setSrvService] = useState('');
  const [srvProtocol, setSrvProtocol] = useState<'tcp' | 'udp'>('tcp');
  const [srvDomain, setSrvDomain] = useState('');
  const [dnssec, setDnssec] = useState(true);
  const [responseView, setResponseView] = useState<DnsResponseView>('simple');
  const [result, setResult] = useState<DnsCheckSuccess | null>(null);
  const [error, setError] = useState<DnsCheckErrorResponse['error'] | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const validationError = validateDnsForm(recordType, queryInput, txtHelper, dkimSelector, srvService, srvDomain);
  const previewName = getDnsPreviewName(recordType, queryInput, txtHelper, dkimSelector, srvService, srvProtocol, srvDomain);

  async function runDnsCheck() {
    const payload = buildDnsPayload({
      mode,
      recordType,
      resolverId,
      queryInput,
      txtHelper,
      dkimSelector,
      srvService,
      srvProtocol,
      srvDomain,
      dnssec,
    });

    setIsLoading(true);
    setResult(null);
    setError(null);

    try {
      const response = await fetch('/api/tools/dns-check', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });
      const body = (await response.json()) as DnsCheckResponse;

      if (!response.ok || !body.ok) {
        const nextError = body.ok ? {
          code: 'DNS_CHECK_FAILED',
          message: 'DNS check failed.',
        } : body.error;

        setError(nextError);
        return;
      }

      setResult(body);
    } catch {
      setError({
        code: 'DNS_CHECK_FAILED',
        message: 'DNS check failed.',
      });
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <Panel title="DNS checker">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Query DNS records through predefined providers, then switch views locally without running another check.
      </p>

      <div className="mt-5 flex flex-wrap gap-2">
        {[
          ['single', 'Single DNS Provider Check'],
          ['burst', 'Burst / Multi-Provider DNS Comparison'],
        ].map(([value, label]) => (
          <button
            key={value}
            className={`rounded-full border px-4 py-2 text-sm font-semibold transition ${
              mode === value
                ? 'border-emerald-400/60 bg-emerald-500/20 text-emerald-100'
                : 'border-white/10 bg-zinc-950/60 text-zinc-300 hover:border-emerald-400/40 hover:text-emerald-200'
            }`}
            type="button"
            onClick={() => setMode(value as DnsMode)}
          >
            {label}
          </button>
        ))}
      </div>

      <DnsCacheNote mode={mode} />

      <div className="mt-5 grid gap-4 xl:grid-cols-[180px_minmax(0,1fr)]">
        <Field>
          <Label>Record type</Label>
          <select
            className={inputClass()}
            value={recordType}
            onChange={(event) => setRecordType(event.target.value as DnsRecordType)}
          >
            {dnsRecordTypes.map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
        </Field>

        {mode === 'single' && (
          <Field>
            <Label>DNS provider</Label>
            <select className={inputClass()} value={resolverId} onChange={(event) => setResolverId(event.target.value)}>
              {dnsSingleResolvers.map((resolver) => (
                <option key={resolver.id} value={resolver.id}>
                  {resolver.name}
                </option>
              ))}
            </select>
          </Field>
        )}
      </div>

      <div className="mt-4">
        <DnsRecordInput
          dkimSelector={dkimSelector}
          queryInput={queryInput}
          recordType={recordType}
          srvDomain={srvDomain}
          srvProtocol={srvProtocol}
          srvService={srvService}
          txtHelper={txtHelper}
          validationError={validationError}
          onDkimSelectorChange={setDkimSelector}
          onQueryChange={setQueryInput}
          onSrvDomainChange={setSrvDomain}
          onSrvProtocolChange={setSrvProtocol}
          onSrvServiceChange={setSrvService}
          onTxtHelperChange={setTxtHelper}
        />
      </div>

      {previewName && (
        <div className="mt-4 rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500">Generated query name</p>
          <p className="mt-2 break-words font-mono text-sm text-emerald-200">{previewName}</p>
        </div>
      )}

      {mode === 'single' && (
        <label className="mt-4 flex items-center gap-3 text-sm font-medium text-zinc-300">
          <input
            checked={dnssec}
            className="size-4 accent-emerald-500"
            type="checkbox"
            onChange={(event) => setDnssec(event.target.checked)}
          />
          Request DNSSEC diagnostics
        </label>
      )}

      <div className="mt-5">
        <button
          className="rounded-xl border border-emerald-500/35 bg-emerald-500 px-5 py-2 text-sm font-semibold text-zinc-950 transition hover:border-emerald-300 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:border-zinc-700 disabled:bg-zinc-800 disabled:text-zinc-500"
          type="button"
          onClick={() => void runDnsCheck()}
          disabled={Boolean(validationError) || isLoading}
          aria-busy={isLoading}
        >
          {isLoading ? 'Running...' : 'Run DNS Check'}
        </button>
      </div>

      {result && <DnsCacheStatusNotice cache={result.cache} />}

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium text-zinc-300">Response view:</span>
        {(['simple', 'advanced', 'raw'] as const).map((view) => (
          <button
            key={view}
            className={`rounded-full border px-3 py-1.5 text-sm font-semibold capitalize transition ${
              responseView === view
                ? 'border-emerald-400/60 bg-emerald-500/20 text-emerald-100'
                : 'border-white/10 bg-zinc-950/60 text-zinc-300 hover:border-emerald-400/40 hover:text-emerald-200'
            }`}
            type="button"
            onClick={() => setResponseView(view)}
          >
            {view}
          </button>
        ))}
      </div>

      {error && <DnsErrorBox error={error} />}

      {result && (
        <div className="mt-6">
          {responseView === 'simple' && <DnsSimpleView result={result} />}
          {responseView === 'advanced' && <DnsAdvancedView result={result} />}
          {responseView === 'raw' && <CommandBlock scrollInside>{JSON.stringify(result, null, 2)}</CommandBlock>}
        </div>
      )}
    </Panel>
  );
}

function DnsCacheNote({ mode }: { mode: DnsMode }) {
  return (
    <div className="mt-5 space-y-3">
      <div className="rounded-2xl border border-emerald-400/25 bg-emerald-500/10 p-4 text-sm leading-6 text-emerald-100">
        {mode === 'single'
          ? 'Single-provider DNS checks are cached by this site for 60 seconds for the exact same query. Cached results are clearly marked with cache age and expiry.'
          : 'Multi-provider DNS checks query several predefined DNS providers and are cached by this site for 5 minutes. Cached results can usually be shown without making another live DNS request.'}
      </div>
      {mode === 'burst' && (
        <div className="rounded-2xl border border-amber-300/25 bg-amber-400/10 p-4 text-sm leading-6 text-amber-100">
          Deep DNSSEC diagnostics are disabled in Multi-Provider mode to keep results fast, reduce backend load, and prevent abuse. Use Single Provider mode for full DNSSEC diagnostics.
        </div>
      )}
    </div>
  );
}

function DnsRecordInput({
  dkimSelector,
  queryInput,
  recordType,
  srvDomain,
  srvProtocol,
  srvService,
  txtHelper,
  validationError,
  onDkimSelectorChange,
  onQueryChange,
  onSrvDomainChange,
  onSrvProtocolChange,
  onSrvServiceChange,
  onTxtHelperChange,
}: {
  dkimSelector: string;
  queryInput: string;
  recordType: DnsRecordType;
  srvDomain: string;
  srvProtocol: 'tcp' | 'udp';
  srvService: string;
  txtHelper: DnsTxtHelper;
  validationError: string;
  onDkimSelectorChange: (value: string) => void;
  onQueryChange: (value: string) => void;
  onSrvDomainChange: (value: string) => void;
  onSrvProtocolChange: (value: 'tcp' | 'udp') => void;
  onSrvServiceChange: (value: string) => void;
  onTxtHelperChange: (value: DnsTxtHelper) => void;
}) {
  const visibleValidationError = shouldShowDnsValidationError(recordType, queryInput, txtHelper, dkimSelector, srvService, srvDomain)
    ? validationError
    : '';

  if (recordType === 'SRV') {
    return (
      <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_140px_minmax(0,1fr)]">
        <Field>
          <Label>Service</Label>
          <ExampleTextInput
            example="sip"
            hasError={Boolean(visibleValidationError)}
            value={srvService}
            onChange={onSrvServiceChange}
          />
        </Field>
        <Field>
          <Label>Protocol</Label>
          <select
            className={inputClass()}
            value={srvProtocol}
            onChange={(event) => onSrvProtocolChange(event.target.value as 'tcp' | 'udp')}
          >
            <option value="tcp">_tcp</option>
            <option value="udp">_udp</option>
          </select>
        </Field>
        <Field>
          <Label>Domain</Label>
          <ExampleTextInput
            example="example.com"
            hasError={Boolean(visibleValidationError)}
            value={srvDomain}
            onChange={onSrvDomainChange}
          />
        </Field>
        {visibleValidationError && <p className="text-xs leading-5 text-red-300 md:col-span-3">{visibleValidationError}</p>}
      </div>
    );
  }

  if (recordType === 'TXT') {
    return (
      <div className="grid gap-4 md:grid-cols-[220px_minmax(0,1fr)]">
        <Field>
          <Label>TXT helper</Label>
          <select
            className={inputClass()}
            value={txtHelper}
            onChange={(event) => onTxtHelperChange(event.target.value as DnsTxtHelper)}
          >
            {(Object.keys(dnsTxtHelperLabels) as DnsTxtHelper[]).map((helper) => (
              <option key={helper} value={helper}>
                {dnsTxtHelperLabels[helper]}
              </option>
            ))}
          </select>
        </Field>
        <Field>
          <Label>{txtHelper === 'dkim' ? 'Domain' : 'Domain/FQDN'}</Label>
          <ExampleTextInput
            example="example.com"
            hasError={Boolean(visibleValidationError)}
            value={queryInput}
            onChange={onQueryChange}
          />
        </Field>
        {txtHelper === 'dkim' && (
          <Field>
            <Label>Selector</Label>
            <ExampleTextInput
              example="selector1"
              hasError={Boolean(visibleValidationError)}
              value={dkimSelector}
              onChange={onDkimSelectorChange}
            />
          </Field>
        )}
        {visibleValidationError && (
          <p className={`text-xs leading-5 text-red-300 ${txtHelper === 'dkim' ? 'md:col-span-2' : 'md:col-span-2'}`}>
            {visibleValidationError}
          </p>
        )}
      </div>
    );
  }

  return (
    <Field>
      <Label>{recordType === 'PTR' ? 'IP address' : 'Domain/FQDN'}</Label>
      <ExampleTextInput
        example={recordType === 'PTR' ? '8.8.8.8' : 'example.com'}
        hasError={Boolean(visibleValidationError)}
        value={queryInput}
        onChange={onQueryChange}
      />
      {visibleValidationError && <p className="text-xs leading-5 text-red-300">{visibleValidationError}</p>}
    </Field>
  );
}

function DnsErrorBox({ error }: { error: DnsCheckErrorResponse['error'] }) {
  const message = error.code === 'RATE_LIMITED'
    ? 'Rate limit reached. Too many live DNS checks were made recently. Please try again later. Cached DNS results may still be available for repeated checks.'
    : error.message;

  return (
    <div className="mt-5 rounded-2xl border border-red-300/35 bg-red-950/40 p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-red-200">Error</p>
      <p className="mt-2 text-sm leading-6 text-red-50">{message}</p>
    </div>
  );
}

function DnsSimpleView({ result }: { result: DnsCheckSuccess }) {
  const records = result.mode === 'burst' ? [] : asDnsRecords(result.records);
  const providers = asDnsProviders(result.providers);
  const diagnostics = asDnsDiagnostics(result.diagnostics);
  const warnings = asDnsStrings(result.warnings);
  const txtDiagnostics = getDnsTxtDiagnostics(diagnostics);
  const hasSpfExplanation = result.mode === 'single' && getDnsSpfDiagnostics(txtDiagnostics).length > 0;

  return (
    <div className="min-w-0 space-y-5">
      <TlsResultSection title="Result">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <ResultItem label="Overall result" value={formatDnsStatus(result.status)} />
          <ResultItem label="Response code" value={formatUnknown(result.responseCode)} />
          <ResultItem label="Resolver/provider" value={formatDnsResolver(result)} />
          <ResultItem label="Duration" value={formatMilliseconds(result.durationMs)} />
        </div>
      </TlsResultSection>

      {result.mode === 'burst' ? (
        <DnsProviderComparison providers={providers} />
      ) : (
        <TlsResultSection title="Main records">
          <DnsRecordList records={records} emptyText="No requested records were returned." />
        </TlsResultSection>
      )}

      {warnings.length > 0 && (
        <TlsResultSection title="Important warnings">
          <DnsStringList values={warnings} />
        </TlsResultSection>
      )}

      {hasSpfExplanation && (
        <TlsResultSection title="TXT/email diagnostics">
          <DnsTxtDiagnostics diagnostics={txtDiagnostics} records={records} compact />
        </TlsResultSection>
      )}

      {diagnostics.length > 0 && (
        <TlsResultSection title="Important diagnostics">
          <DnsDiagnosticList diagnostics={diagnostics.slice(0, 6)} />
        </TlsResultSection>
      )}
    </div>
  );
}

function DnsAdvancedView({ result }: { result: DnsCheckSuccess }) {
  const answer = asDnsRecords(result.answer);
  const authority = asDnsRecords(result.authority);
  const additional = asDnsRecords(result.additional);
  const providers = asDnsProviders(result.providers);
  const diagnostics = asDnsDiagnostics(result.diagnostics);
  const warnings = asDnsStrings(result.warnings);
  const cnameRecords = answer.filter((record) => record.type === 'CNAME');
  const mxDiagnostics = diagnostics.filter((diagnostic) => {
    const diagnosticId = getDnsDiagnosticId(diagnostic);

    return diagnosticId.startsWith('mx_') || diagnosticId.includes('mx');
  });
  const txtDiagnostics = getDnsTxtDiagnostics(diagnostics);

  return (
    <div className="min-w-0 space-y-5">
      <TlsResultSection title="Query">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          <ResultItem label="Input" value={result.query?.input} />
          <ResultItem label="Query name" value={result.query?.queryName} />
          <ResultItem label="Record type" value={result.query?.recordType} />
          <ResultItem label="Service" value={result.query?.service} />
          <ResultItem label="Protocol" value={result.query?.protocol} />
          <ResultItem label="Domain" value={result.query?.domain} />
        </div>
      </TlsResultSection>

      <TlsResultSection title="Response metadata">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <ResultItem label="Status" value={formatDnsStatus(result.status)} />
          <ResultItem label="Response code" value={formatUnknown(result.responseCode)} />
          <ResultItem label="Duration" value={formatMilliseconds(result.durationMs)} />
          <ResultItem label="Mode" value={result.mode} />
        </div>
      </TlsResultSection>

      <TlsResultSection title="Resolver metadata">
        <pre className="max-w-full whitespace-pre-wrap break-words rounded-xl border border-white/10 bg-zinc-950 p-4 text-sm leading-6 text-zinc-100 [overflow-wrap:anywhere]">
          {JSON.stringify({ resolver: result.resolver, provider: result.provider }, null, 2)}
        </pre>
      </TlsResultSection>

      {result.mode === 'burst' && <DnsProviderComparison providers={providers} />}

      <TlsResultSection title="Answer section">
        <DnsRecordList records={answer} emptyText="No answer records were returned." />
      </TlsResultSection>

      <TlsResultSection title="Authority section">
        <DnsRecordList records={authority} emptyText="No authority records were returned." />
      </TlsResultSection>

      <TlsResultSection title="Additional section">
        <DnsRecordList records={additional} emptyText="No additional records were returned." />
      </TlsResultSection>

      <TlsResultSection title="DNSSEC diagnostics">
        <pre className="max-w-full whitespace-pre-wrap break-words rounded-xl border border-white/10 bg-zinc-950 p-4 text-sm leading-6 text-zinc-100 [overflow-wrap:anywhere]">
          {JSON.stringify(result.dnssec, null, 2)}
        </pre>
      </TlsResultSection>

      {mxDiagnostics.length > 0 && (
        <TlsResultSection title="MX diagnostics">
          <DnsDiagnosticList diagnostics={mxDiagnostics} />
        </TlsResultSection>
      )}

      {result.mode === 'single' && txtDiagnostics.length > 0 && (
        <TlsResultSection title="TXT/email diagnostics">
          <DnsTxtDiagnostics diagnostics={txtDiagnostics} records={answer} warnings={warnings} />
        </TlsResultSection>
      )}

      {cnameRecords.length > 0 && (
        <TlsResultSection title="CNAME chain">
          <DnsRecordList records={cnameRecords} emptyText="No CNAME records were returned." />
        </TlsResultSection>
      )}

      <TlsResultSection title="All diagnostics">
        <DnsDiagnosticList diagnostics={diagnostics} />
      </TlsResultSection>

      <TlsResultSection title="All warnings">
        <DnsStringList values={warnings} />
      </TlsResultSection>
    </div>
  );
}

function DnsCacheStatusNotice({ cache }: { cache: DnsCacheMetadata }) {
  const cacheDetails = [
    ['Served from this site\'s cache', cache.fromCache ? 'Yes' : 'No'],
    ['Cache age', formatSeconds(cache.cacheAgeSeconds)],
    ['Expires in', formatSeconds(cache.cacheExpiresInSeconds)],
    ['Cache TTL', formatSeconds(cache.cacheTtlSeconds)],
  ].filter((detail): detail is [string, string] => Boolean(detail[1]));

  return (
    <aside className="mt-4 rounded-2xl border border-emerald-400/25 bg-emerald-500/10 p-4 text-sm text-emerald-50">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-emerald-200">Cache status</p>
          <p className="mt-1 font-semibold text-emerald-50">
            {cache.fromCache ? 'Served from this site\'s cache' : 'Live DNS check'}
          </p>
        </div>
        <dl className="grid gap-x-4 gap-y-2 sm:grid-cols-2">
          {cacheDetails.map(([label, value]) => (
            <div key={label}>
              <dt className="text-xs font-semibold uppercase tracking-[0.14em] text-emerald-200/80">{label}</dt>
              <dd className="mt-0.5 font-mono text-sm text-emerald-50">{value}</dd>
            </div>
          ))}
        </dl>
      </div>
    </aside>
  );
}

function DnsProviderComparison({ providers }: { providers?: DnsProviderResult[] | null }) {
  const safeProviders = asDnsProviders(providers);

  if (safeProviders.length === 0) {
    return (
      <TlsResultSection title="Provider comparison">
        <p className="text-sm text-zinc-400">No provider comparison data was returned.</p>
      </TlsResultSection>
    );
  }

  return (
    <TlsResultSection title="Provider comparison">
      <div className="grid min-w-0 gap-3">
        {safeProviders.map((provider, index) => {
          const resolver = provider.resolver || provider.provider;
          const records = asDnsRecords(provider.records);
          const warnings = asDnsStrings(provider.warnings);

          return (
            <article key={resolver?.id || `provider-${index}`} className="min-w-0 rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
              <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <h4 className="break-words text-sm font-semibold text-zinc-100 [overflow-wrap:anywhere]">
                    {resolver?.name || 'Unknown provider'}
                  </h4>
                  <p className="mt-1 break-words text-xs uppercase tracking-[0.14em] text-zinc-500 [overflow-wrap:anywhere]">
                    {resolver?.profile || resolver?.category || 'Provider'}
                  </p>
                </div>
                <span className="w-fit rounded-full border border-emerald-400/25 bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-200">
                  {formatDnsStatus(provider.status) || 'Unknown'}
                </span>
              </div>
              <dl className="mt-4 grid min-w-0 gap-3 md:grid-cols-2 xl:grid-cols-3">
                <DnsDetailItem label="Response" value={provider.responseCode || provider.status || '-'} mono />
                <DnsDetailItem label="Records" value={formatDnsRecordValues(records)} />
                <DnsDetailItem label="TTL" value={formatDnsTtls(records)} mono />
                <DnsDetailItem label="Duration" value={formatMilliseconds(provider.durationMs) || '-'} mono />
                <DnsDetailItem label="Warnings" value={warnings.length ? warnings.join(' ') : '-'} />
              </dl>
            </article>
          );
        })}
      </div>
    </TlsResultSection>
  );
}

function DnsRecordList({ records, emptyText }: { records?: DnsRecord[] | null; emptyText: string }) {
  const safeRecords = asDnsRecords(records);

  if (safeRecords.length === 0) {
    return <p className="text-sm text-zinc-400">{emptyText}</p>;
  }

  return (
    <div className="min-w-0 space-y-3">
      {safeRecords.map((record, index) => (
        <article key={`${record.name || 'record'}-${record.type || 'unknown'}-${index}`} className="min-w-0 rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <dl className="grid min-w-0 gap-3 md:grid-cols-2 xl:grid-cols-4">
            <DnsDetailItem label="Type" value={record.type || 'Record'} />
            <DnsDetailItem label="Name" value={record.name || '-'} mono />
            <DnsDetailItem label="TTL" value={record.ttl === undefined ? '-' : `${record.ttl} seconds`} mono />
            <DnsDetailItem label="Value" value={formatDnsRecord(record)} mono />
            {record.type === 'MX' && (
              <>
                <DnsDetailItem label="Preference" value={formatUnknown(record.preference) || '-'} mono />
                <DnsDetailItem label="Exchange" value={record.exchange || '-'} mono />
                <DnsDetailItem label="Resolved A records" value={record.resolvedA?.join(', ') || '-'} mono />
                <DnsDetailItem label="Resolved AAAA records" value={record.resolvedAAAA?.join(', ') || '-'} mono />
              </>
            )}
          </dl>
        </article>
      ))}
    </div>
  );
}

function DnsDetailItem({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-semibold uppercase tracking-[0.14em] text-zinc-500">{label}</dt>
      <dd className={`mt-1 break-words text-sm leading-6 text-zinc-100 [overflow-wrap:anywhere] ${mono ? 'font-mono' : ''}`}>
        {value || '-'}
      </dd>
    </div>
  );
}

function DnsDiagnosticList({ diagnostics }: { diagnostics?: DnsDiagnostic[] | null }) {
  const safeDiagnostics = asDnsDiagnostics(diagnostics);

  if (safeDiagnostics.length === 0) {
    return <p className="text-sm text-zinc-400">No diagnostics were returned.</p>;
  }

  return (
    <div className="min-w-0 space-y-3">
      {safeDiagnostics.map((diagnostic, index) => {
        const diagnosticId = getDnsDiagnosticId(diagnostic);

        return (
          <div key={`${diagnosticId}-${index}`} className="min-w-0 rounded-xl border border-white/10 bg-zinc-950/60 p-4">
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <p className="break-words font-mono text-sm font-semibold text-zinc-100 [overflow-wrap:anywhere]">
                {formatDiagnosticName(diagnosticId)}
              </p>
              {diagnostic.status && (
                <span className="rounded-full border border-white/10 bg-zinc-900 px-2 py-0.5 text-xs font-semibold text-zinc-300">
                  {diagnostic.status}
                </span>
              )}
            </div>
            {diagnostic.message && (
              <p className="mt-2 break-words text-sm leading-6 text-zinc-300 [overflow-wrap:anywhere]">{diagnostic.message}</p>
            )}
            <pre className="mt-3 max-w-full whitespace-pre-wrap break-words text-xs leading-5 text-zinc-300 [overflow-wrap:anywhere]">
              {JSON.stringify(diagnostic, null, 2)}
            </pre>
          </div>
        );
      })}
    </div>
  );
}

function DnsTxtDiagnostics({
  diagnostics,
  records,
  warnings,
  compact = false,
}: {
  diagnostics?: DnsDiagnostic[] | null;
  records?: DnsRecord[] | null;
  warnings?: string[] | null;
  compact?: boolean;
}) {
  const safeDiagnostics = asDnsDiagnostics(diagnostics);
  const spfDiagnostics = getDnsSpfDiagnostics(safeDiagnostics);
  const spfWarnings = asDnsStrings(warnings).filter((warning) => warning.toLowerCase().includes('spf'));
  const groups = [
    ['DKIM', safeDiagnostics.filter((diagnostic) => getDnsDiagnosticId(diagnostic) === 'dkim')],
    ['DMARC', safeDiagnostics.filter((diagnostic) => getDnsDiagnosticId(diagnostic) === 'dmarc')],
    ['Microsoft 365 verification', safeDiagnostics.filter((diagnostic) => getDnsDiagnosticId(diagnostic) === 'microsoft_365_verification')],
    ['Google verification', safeDiagnostics.filter((diagnostic) => getDnsDiagnosticId(diagnostic) === 'google_verification')],
    ["ACME / Let's Encrypt", safeDiagnostics.filter((diagnostic) => getDnsDiagnosticId(diagnostic) === 'acme_challenge')],
  ] as const;

  return (
    <div className="min-w-0 space-y-4">
      {spfDiagnostics.map((diagnostic, index) => (
        <DnsSpfExplanation
          key={`${String(diagnostic.value || 'spf')}-${index}`}
          compact={compact}
          diagnostic={diagnostic}
          records={records}
          warnings={spfWarnings}
        />
      ))}
      {!compact && groups.map(([title, groupDiagnostics]) => (
        <div key={title} className="min-w-0 rounded-xl border border-white/10 bg-zinc-950/60 p-4">
          <h4 className="text-sm font-semibold text-zinc-100">{title}</h4>
          <div className="mt-3 min-w-0">
            <DnsDiagnosticList diagnostics={groupDiagnostics} />
          </div>
        </div>
      ))}
    </div>
  );
}

function DnsSpfExplanation({
  diagnostic,
  records,
  warnings,
  compact,
}: {
  diagnostic: DnsDiagnostic;
  records?: DnsRecord[] | null;
  warnings?: string[] | null;
  compact: boolean;
}) {
  const spfValue = typeof diagnostic.value === 'string' ? diagnostic.value : '';
  const mechanisms = getDnsSpfMechanisms(diagnostic);
  const ttl = getDnsSpfTtl(records, spfValue);
  const visibleMechanisms = compact ? mechanisms.slice(0, 8) : mechanisms;
  const hiddenCount = Math.max(0, mechanisms.length - visibleMechanisms.length);
  const parserDetails = [
    ['Lookup count estimate', formatUnknown(diagnostic.lookupCountEstimate)],
    ['Include mechanisms', asDnsStrings(diagnostic.include as string[] | null | undefined).join(', ') || null],
    ['Redirect', typeof diagnostic.redirect === 'string' ? diagnostic.redirect : null],
    ['All mechanism', typeof diagnostic.all === 'string' ? diagnostic.all : null],
  ].filter((detail): detail is [string, string] => Boolean(detail[1]));

  return (
    <article className="min-w-0 rounded-xl border border-white/10 bg-zinc-950/60 p-4">
      <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h4 className="text-sm font-semibold text-zinc-100">SPF record</h4>
          {spfValue && !compact && (
            <p className="mt-2 break-words font-mono text-xs leading-5 text-zinc-400 [overflow-wrap:anywhere]">
              {spfValue}
            </p>
          )}
        </div>
        {ttl !== null && (
          <span className="w-fit rounded-full border border-emerald-400/25 bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-200">
            DNS TTL: {formatDnsTtlShort(ttl)}
          </span>
        )}
      </div>

      {ttl === null && (
        <p className="mt-3 text-sm leading-6 text-zinc-400">
          Resolver cache lifetime was not included with this TXT answer.
        </p>
      )}
      {ttl !== null && !compact && (
        <p className="mt-3 text-sm leading-6 text-zinc-400">
          Resolvers may cache this TXT answer for up to {formatDnsTtlShort(ttl)}.
        </p>
      )}

      <div className="mt-4 min-w-0 space-y-2">
        {visibleMechanisms.length > 0 ? visibleMechanisms.map((mechanism, index) => (
          <DnsSpfMechanismRow
            key={`${mechanism.token || 'spf-token'}-${index}`}
            defaultDomain={typeof diagnostic.queryName === 'string' ? diagnostic.queryName : null}
            mechanism={mechanism}
            isFirst={index === 0}
          />
        )) : (
          <p className="text-sm text-zinc-400">No SPF mechanisms were parsed from this record.</p>
        )}
      </div>

      {hiddenCount > 0 && (
        <p className="mt-3 text-sm leading-6 text-zinc-400">
          {hiddenCount} more SPF {hiddenCount === 1 ? 'rule is' : 'rules are'} shown in Advanced view.
        </p>
      )}

      {!compact && warnings && warnings.length > 0 && (
        <div className="mt-4 rounded-xl border border-amber-300/25 bg-amber-400/10 p-3">
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-100">SPF warnings</p>
          <div className="mt-2">
            <DnsStringList values={warnings} />
          </div>
        </div>
      )}

      {!compact && parserDetails.length > 0 && (
        <dl className="mt-4 grid min-w-0 gap-3 md:grid-cols-2">
          {parserDetails.map(([label, value]) => (
            <DnsDetailItem key={label} label={label} value={value} mono={label !== 'Lookup count estimate'} />
          ))}
        </dl>
      )}
    </article>
  );
}

function DnsSpfMechanismRow({
  mechanism,
  defaultDomain,
  isFirst,
}: {
  mechanism: DnsSpfMechanism;
  defaultDomain: string | null;
  isFirst: boolean;
}) {
  const warning = getDnsSpfMechanismWarning(mechanism);

  return (
    <div className={`min-w-0 rounded-xl border p-3 ${
      warning
        ? 'border-amber-300/30 bg-amber-400/10'
        : 'border-white/10 bg-zinc-900/70'
    }`}>
      <div className="grid min-w-0 gap-2 lg:grid-cols-[minmax(0,1fr)_minmax(180px,0.38fr)] lg:items-start">
        <div className="min-w-0">
          <p className="break-words text-sm leading-6 text-zinc-100 [overflow-wrap:anywhere]">
            {describeDnsSpfMechanism(mechanism, defaultDomain, isFirst)}
          </p>
          {warning && (
            <p className="mt-1 break-words text-xs font-semibold leading-5 text-amber-100 [overflow-wrap:anywhere]">
              {warning}
            </p>
          )}
        </div>
        <code className="min-w-0 break-words rounded-lg border border-white/10 bg-zinc-950 px-2 py-1 font-mono text-xs leading-5 text-zinc-400 [overflow-wrap:anywhere]">
          {mechanism.token || '-'}
        </code>
      </div>
    </div>
  );
}

function DnsStringList({ values }: { values?: string[] | null }) {
  const safeValues = asDnsStrings(values);

  if (safeValues.length === 0) {
    return <p className="text-sm text-zinc-400">None.</p>;
  }

  return (
    <ul className="min-w-0 space-y-2 text-sm leading-6 text-zinc-300">
      {safeValues.map((value, index) => (
        <li key={`${value}-${index}`} className="min-w-0 break-words rounded-xl border border-white/10 bg-zinc-950/60 px-3 py-2 [overflow-wrap:anywhere]">
          {value}
        </li>
      ))}
    </ul>
  );
}

function buildDnsPayload({
  mode,
  recordType,
  resolverId,
  queryInput,
  txtHelper,
  dkimSelector,
  srvService,
  srvProtocol,
  srvDomain,
  dnssec,
}: {
  mode: DnsMode;
  recordType: DnsRecordType;
  resolverId: string;
  queryInput: string;
  txtHelper: DnsTxtHelper;
  dkimSelector: string;
  srvService: string;
  srvProtocol: 'tcp' | 'udp';
  srvDomain: string;
  dnssec: boolean;
}) {
  const payload: Record<string, unknown> = {
    mode,
    recordType,
  };

  if (mode === 'single') {
    payload.resolverId = resolverId;
    payload.dnssec = dnssec;
  }

  if (recordType === 'SRV') {
    payload.service = srvService.trim();
    payload.protocol = srvProtocol;
    payload.domain = srvDomain.trim();
    return payload;
  }

  payload.query = getDnsQueryInput(recordType, queryInput, txtHelper, dkimSelector);
  return payload;
}

function getDnsQueryInput(recordType: DnsRecordType, queryInput: string, txtHelper: DnsTxtHelper, dkimSelector: string) {
  const value = queryInput.trim();

  if (recordType !== 'TXT') {
    return value;
  }

  if (txtHelper === 'dkim') {
    return `${dkimSelector.trim()}._domainkey.${value}`;
  }

  if (txtHelper === 'dmarc') {
    return `_dmarc.${value}`;
  }

  if (txtHelper === 'acme') {
    return `_acme-challenge.${value}`;
  }

  return value;
}

function getDnsPreviewName(
  recordType: DnsRecordType,
  queryInput: string,
  txtHelper: DnsTxtHelper,
  dkimSelector: string,
  srvService: string,
  srvProtocol: 'tcp' | 'udp',
  srvDomain: string,
) {
  if (recordType === 'SRV') {
    const service = srvService.trim().replace(/^_/, '');
    const domain = srvDomain.trim();

    return service && domain ? `_${service}._${srvProtocol}.${domain}` : '';
  }

  if (recordType === 'TXT' && txtHelper !== 'normal' && txtHelper !== 'spf') {
    return getDnsQueryInput(recordType, queryInput, txtHelper, dkimSelector);
  }

  return '';
}

function validateDnsForm(
  recordType: DnsRecordType,
  queryInput: string,
  txtHelper: DnsTxtHelper,
  dkimSelector: string,
  srvService: string,
  srvDomain: string,
) {
  if (recordType === 'SRV') {
    if (!srvService.trim() || !srvDomain.trim()) {
      return 'Service and domain are required for SRV checks.';
    }

    if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,61}$/.test(srvService.trim().replace(/^_/, ''))) {
      return 'Use a valid SRV service such as sip or xmpp-server.';
    }

    return isLikelyDnsName(srvDomain) ? '' : 'Enter a valid public domain for SRV checks.';
  }

  if (!queryInput.trim()) {
    return recordType === 'PTR' ? 'IP address is required.' : 'Domain/FQDN is required.';
  }

  if (recordType === 'PTR') {
    return isAllowedDnsPtrAddress(queryInput.trim()) ? '' : 'Enter a valid public IPv4 or IPv6 address.';
  }

  if (recordType === 'TXT' && txtHelper === 'dkim') {
    if (!dkimSelector.trim()) {
      return 'Selector is required for DKIM TXT checks.';
    }

    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$/.test(dkimSelector.trim())) {
      return 'Use a valid DKIM selector.';
    }
  }

  return isLikelyDnsName(queryInput) ? '' : 'Enter a valid public domain or FQDN.';
}

function shouldShowDnsValidationError(
  recordType: DnsRecordType,
  queryInput: string,
  txtHelper: DnsTxtHelper,
  dkimSelector: string,
  srvService: string,
  srvDomain: string,
) {
  if (recordType === 'SRV') {
    return Boolean(srvService.trim() || srvDomain.trim());
  }

  if (recordType === 'TXT' && txtHelper === 'dkim') {
    return Boolean(queryInput.trim() || dkimSelector.trim());
  }

  return Boolean(queryInput.trim());
}

function isLikelyDnsName(value: string) {
  const normalizedValue = value.trim().replace(/\.$/, '').toLowerCase();

  return (
    normalizedValue.length > 0 &&
    normalizedValue.length <= 253 &&
    normalizedValue.includes('.') &&
    !normalizedValue.includes('..') &&
    !/[:/?#@[\]\\\s]/.test(normalizedValue) &&
    normalizedValue.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
  );
}

function isAllowedDnsPtrAddress(value: string) {
  if (!isValidIpAddress(value)) {
    return false;
  }

  return isValidIpv4Address(value) ? !isBlockedDnsPtrIpv4Address(value) : !isBlockedDnsPtrIpv6Address(value);
}

function isBlockedDnsPtrIpv4Address(value: string) {
  const address = ipv4AddressToNumber(value);
  const blockedRanges: Array<[string, number]> = [
    ['0.0.0.0', 8],
    ['10.0.0.0', 8],
    ['100.64.0.0', 10],
    ['127.0.0.0', 8],
    ['169.254.0.0', 16],
    ['172.16.0.0', 12],
    ['192.0.0.0', 24],
    ['192.0.2.0', 24],
    ['192.168.0.0', 16],
    ['198.18.0.0', 15],
    ['198.51.100.0', 24],
    ['203.0.113.0', 24],
    ['224.0.0.0', 4],
    ['240.0.0.0', 4],
    ['255.255.255.255', 32],
    ['169.254.169.254', 32],
  ];

  return blockedRanges.some(([range, prefix]) => ipv4NumberInCidr(address, ipv4AddressToNumber(range), prefix));
}

function ipv4AddressToNumber(value: string) {
  return value.split('.').reduce((address, octet) => ((address << 8) + Number(octet)) >>> 0, 0);
}

function ipv4NumberInCidr(address: number, range: number, prefix: number) {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;

  return (address & mask) === (range & mask);
}

function isBlockedDnsPtrIpv6Address(value: string) {
  const address = parseIpAddress(value);
  const blockedRanges: Array<[string, number]> = [
    ['::', 128],
    ['::1', 128],
    ['100::', 64],
    ['2001:db8::', 32],
    ['fc00::', 7],
    ['fe80::', 10],
    ['ff00::', 8],
  ];

  return blockedRanges.some(([range, prefix]) => ipv6AddressInPrefix(address, parseIpAddress(range), prefix));
}

function ipv6AddressInPrefix(address: Uint8Array, range: Uint8Array, prefix: number) {
  const fullBytes = Math.floor(prefix / 8);
  const partialBits = prefix % 8;

  for (let index = 0; index < fullBytes; index += 1) {
    if (address[index] !== range[index]) {
      return false;
    }
  }

  if (partialBits === 0) {
    return true;
  }

  const mask = (0xff << (8 - partialBits)) & 0xff;

  return (address[fullBytes] & mask) === (range[fullBytes] & mask);
}

function formatDnsResolver(result: DnsCheckSuccess) {
  if (result.provider) {
    return result.provider.name;
  }

  if (result.resolver && 'providers' in result.resolver) {
    const providers = Array.isArray(result.resolver.providers) ? result.resolver.providers : [];

    return `${providers.length} predefined providers`;
  }

  return (result.resolver as DnsProviderSummary | null | undefined)?.name || 'Unknown provider';
}

function formatDnsStatus(status: string | null | undefined) {
  return status ? dnsStatusLabels[status] || status : null;
}

function formatDnsTtls(records: DnsRecord[] | null | undefined) {
  const ttls = Array.from(new Set(asDnsRecords(records).map((record) => record.ttl).filter((ttl): ttl is number => typeof ttl === 'number')));

  return ttls.length ? ttls.join(', ') : '-';
}

function formatDnsRecordValues(records: DnsRecord[] | null | undefined) {
  const safeRecords = asDnsRecords(records);

  if (safeRecords.length === 0) {
    return '-';
  }

  return safeRecords.map(formatDnsRecord).join('; ');
}

function formatDnsRecord(record: DnsRecord) {
  if (record.type === 'A' || record.type === 'AAAA') {
    return record.address || '-';
  }

  if (record.type === 'CNAME') {
    return record.target || '-';
  }

  if (record.type === 'NS' || record.type === 'PTR') {
    return record.host || '-';
  }

  if (record.type === 'TXT') {
    return record.value || record.chunks?.join('') || '-';
  }

  if (record.type === 'MX') {
    return `${record.preference ?? '-'} ${record.exchange || '-'}`;
  }

  if (record.type === 'SOA') {
    return `mname=${formatUnknown(record.mname)} rname=${formatUnknown(record.rname)} serial=${formatUnknown(record.serial)}`;
  }

  if (record.type === 'SRV') {
    return `${formatUnknown(record.priority)} ${formatUnknown(record.weight)} ${formatUnknown(record.port)} ${formatUnknown(record.target)}`;
  }

  if (record.type === 'CAA') {
    return `${formatUnknown(record.flags)} ${formatUnknown(record.tag)} ${formatUnknown(record.value)}`;
  }

  return JSON.stringify(record);
}

function asDnsRecords(records: DnsRecord[] | null | undefined) {
  return Array.isArray(records) ? records : [];
}

function asDnsDiagnostics(diagnostics: DnsDiagnostic[] | null | undefined) {
  return Array.isArray(diagnostics) ? diagnostics : [];
}

function asDnsProviders(providers: DnsProviderResult[] | null | undefined) {
  return Array.isArray(providers) ? providers : [];
}

function asDnsStrings(values: string[] | null | undefined) {
  return Array.isArray(values) ? values.filter((value): value is string => typeof value === 'string') : [];
}

function getDnsDiagnosticId(diagnostic: DnsDiagnostic) {
  return typeof diagnostic.id === 'string' && diagnostic.id ? diagnostic.id : 'diagnostic';
}

function getDnsTxtDiagnostics(diagnostics: DnsDiagnostic[]) {
  return diagnostics.filter((diagnostic) => [
    'spf',
    'dkim',
    'dmarc',
    'microsoft_365_verification',
    'google_verification',
    'acme_challenge',
  ].includes(getDnsDiagnosticId(diagnostic)));
}

function getDnsSpfDiagnostics(diagnostics: DnsDiagnostic[] | null | undefined) {
  return asDnsDiagnostics(diagnostics).filter((diagnostic) => getDnsDiagnosticId(diagnostic) === 'spf');
}

function getDnsSpfMechanisms(diagnostic: DnsDiagnostic) {
  const detailed = Array.isArray(diagnostic.mechanismDetails) ? diagnostic.mechanismDetails : [];
  const structured = detailed.filter(isDnsSpfMechanism);

  if (structured.length > 0) {
    return structured;
  }

  return Array.isArray(diagnostic.mechanisms)
    ? diagnostic.mechanisms.filter((token): token is string => typeof token === 'string').map(parseDnsSpfToken)
    : [];
}

function isDnsSpfMechanism(value: unknown): value is DnsSpfMechanism {
  return typeof value === 'object' && value !== null && typeof (value as DnsSpfMechanism).token === 'string';
}

function parseDnsSpfToken(token: string): DnsSpfMechanism {
  const qualifier = /^[+?~-]/.test(token) ? token[0] : '+';
  const body = qualifier === token[0] ? token.slice(1) : token;
  const modifierMatch = body.match(/^(redirect|exp)=(.+)$/i);

  if (modifierMatch) {
    return {
      token,
      qualifier: null,
      result: null,
      mechanism: modifierMatch[1].toLowerCase(),
      value: modifierMatch[2],
      modifier: true,
      valid: true,
    };
  }

  const mechanismMatch = body.match(/^([a-z0-9]+)(?::([^/]+))?(?:\/(.+))?$/i);

  return {
    token,
    qualifier,
    result: ({ '+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral' } as Record<string, string>)[qualifier] || 'pass',
    mechanism: mechanismMatch?.[1]?.toLowerCase() || 'unknown',
    value: mechanismMatch?.[2] || null,
    prefix: mechanismMatch?.[3] || null,
    modifier: false,
    valid: Boolean(mechanismMatch),
  };
}

function getDnsSpfTtl(records: DnsRecord[] | null | undefined, spfValue: string) {
  const txtRecords = asDnsRecords(records).filter((record) => record.type === 'TXT');
  const matchingRecord = txtRecords.find((record) => {
    const value = record.value || record.chunks?.join('') || '';

    return value === spfValue || value.toLowerCase().startsWith('v=spf1');
  });

  return typeof matchingRecord?.ttl === 'number' && Number.isFinite(matchingRecord.ttl) ? matchingRecord.ttl : null;
}

function formatDnsTtlShort(seconds: number) {
  if (seconds % 3600 === 0) {
    return `${seconds / 3600}h`;
  }

  if (seconds % 60 === 0) {
    return `${seconds / 60}m`;
  }

  return `${seconds}s`;
}

function describeDnsSpfMechanism(mechanism: DnsSpfMechanism, defaultDomain: string | null, isFirst: boolean) {
  const kind = String(mechanism.mechanism || 'unknown').toLowerCase();
  const value = typeof mechanism.value === 'string' && mechanism.value ? mechanism.value : null;
  const prefix = typeof mechanism.prefix === 'string' && mechanism.prefix ? mechanism.prefix : null;
  const domain = value || defaultDomain || 'this domain';
  const lead = isFirst ? '' : 'Or else, ';
  const sentenceVerb = (verb: string) => (isFirst ? `${verb.charAt(0).toUpperCase()}${verb.slice(1)}` : `${lead}${verb}`);

  if (kind === 'redirect') {
    return `${sentenceVerb('redirect')} SPF evaluation to ${domain} if no previous rule matches.`;
  }

  if (kind === 'exp') {
    return `${sentenceVerb('use')} ${domain} for SPF failure explanation text.`;
  }

  if (kind === 'all') {
    return `${lead}${describeDnsSpfAllResult(mechanism)}.`;
  }

  if (!mechanism.valid || kind === 'unknown') {
    return 'Unknown or unsupported SPF mechanism.';
  }

  const result = getDnsSpfResultPhrase(mechanism, isFirst);

  if (kind === 'include') {
    return `${sentenceVerb('include')} the SPF record at ${domain} and ${getDnsSpfResultPhrase(mechanism, false)} if it matches the sender's IP.`;
  }

  if (kind === 'a') {
    return `${lead}${result} if the email sender's IP is in the A or AAAA records of ${domain}${formatDnsSpfPrefix(prefix)}.`;
  }

  if (kind === 'mx') {
    return `${lead}${result} if the email sender's IP is in the MX records of ${domain}${formatDnsSpfPrefix(prefix)}.`;
  }

  if (kind === 'ip4') {
    return prefix
      ? `${lead}${result} if the email sender's IP matches the IPv4 range ${domain}/${prefix}.`
      : `${lead}${result} if the email sender's IP is ${domain}.`;
  }

  if (kind === 'ip6') {
    return prefix
      ? `${lead}${result} if the email sender's IP matches the IPv6 range ${domain}/${prefix}.`
      : `${lead}${result} if the email sender's IP is ${domain}.`;
  }

  if (kind === 'exists') {
    return `${lead}${result} if ${domain} resolves in DNS.`;
  }

  if (kind === 'ptr') {
    return `${lead}${result} if reverse DNS validates against ${domain}.`;
  }

  return 'Unknown or unsupported SPF mechanism.';
}

function describeDnsSpfAllResult(mechanism: DnsSpfMechanism) {
  const result = String(mechanism.result || 'pass').toLowerCase();

  if (result === 'fail') {
    return 'mark the email as fail';
  }

  if (result === 'softfail') {
    return 'mark the email as soft fail';
  }

  if (result === 'neutral') {
    return 'return neutral';
  }

  return 'pass all senders';
}

function getDnsSpfResultPhrase(mechanism: DnsSpfMechanism, isFirst: boolean) {
  const result = String(mechanism.result || 'pass').toLowerCase();

  if (result === 'fail') {
    return isFirst ? 'Fail' : 'fail';
  }

  if (result === 'softfail') {
    return isFirst ? 'Soft fail' : 'soft fail';
  }

  if (result === 'neutral') {
    return isFirst ? 'Return neutral' : 'return neutral';
  }

  return isFirst ? 'Pass' : 'pass';
}

function formatDnsSpfPrefix(prefix: string | null) {
  return prefix ? ` within prefix /${prefix}` : '';
}

function getDnsSpfMechanismWarning(mechanism: DnsSpfMechanism) {
  const kind = String(mechanism.mechanism || 'unknown').toLowerCase();
  const qualifier = mechanism.qualifier || '+';

  if (kind === 'all' && qualifier === '+') {
    return 'Dangerous/permissive: this passes all senders.';
  }

  if (kind === 'ptr') {
    return 'Deprecated: ptr mechanisms are slow and unreliable.';
  }

  if (mechanism.valid === false || kind === 'unknown') {
    return 'Invalid-looking or unsupported mechanism.';
  }

  return null;
}

function formatSeconds(value: unknown) {
  return typeof value === 'number' && Number.isFinite(value) ? `${value} seconds` : null;
}

function formatMilliseconds(value: unknown) {
  return typeof value === 'number' && Number.isFinite(value) ? `${value} ms` : null;
}

function formatUnknown(value: unknown) {
  if (value === null || value === undefined || value === '') {
    return null;
  }

  return typeof value === 'string' ? value : String(value);
}

function formatDiagnosticName(value: string) {
  return value.replace(/_/g, ' ').replace(/\b\w/g, (character) => character.toUpperCase());
}

function FirewallGenerator() {
  const [source, setSource] = useState(firewallExamples.source);
  const [useSourcePort, setUseSourcePort] = useState(false);
  const [sourcePort, setSourcePort] = useState(firewallExamples.sourcePort);
  const [useDestination, setUseDestination] = useState(false);
  const [destination, setDestination] = useState(firewallExamples.destination);
  const [port, setPort] = useState(firewallExamples.destinationPort);
  const [isPortExample, setIsPortExample] = useState(true);
  const [protocol, setProtocol] = useState('tcp');
  const sourceError = validateIpv4Cidr(source);
  const sourcePortError = protocol !== 'icmp' && useSourcePort ? validatePort(sourcePort) : null;
  const portError = protocol !== 'icmp' ? validatePort(port) : null;
  const destinationError = useDestination ? validateIpv4Cidr(destination) : null;
  const target = useDestination ? destination : 'any';
  const sourcePortClause = protocol !== 'icmp' && useSourcePort ? ` port ${sourcePort}` : '';
  const command =
    protocol === 'icmp'
      ? `sudo ufw allow proto icmp from ${source} to ${target}`
      : `sudo ufw allow proto ${protocol} from ${source}${sourcePortClause} to ${target} port ${port}`;

  return (
    <Panel title="UFW command generator">
      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_220px]">
        <div>
          <div className="grid gap-4 sm:grid-cols-3">
            <Field>
              <Label>Source IPv4</Label>
              <input
                className={inputClass(Boolean(sourceError), source === firewallExamples.source)}
                value={source}
                onChange={(event) => setSource(event.target.value)}
                onFocus={() => clearExampleValue(source, firewallExamples.source, setSource)}
                onBlur={() => restoreExampleValue(source, firewallExamples.source, setSource)}
              />
              {sourceError && <p className="text-xs leading-5 text-red-300">{sourceError}</p>}
            </Field>
            {protocol !== 'icmp' && useSourcePort && (
              <Field>
                <Label>Source port</Label>
                <input
                  className={inputClass(Boolean(sourcePortError), sourcePort === firewallExamples.sourcePort)}
                  value={sourcePort}
                  onChange={(event) => setSourcePort(event.target.value)}
                  onFocus={() => clearExampleValue(sourcePort, firewallExamples.sourcePort, setSourcePort)}
                  onBlur={() => restoreExampleValue(sourcePort, firewallExamples.sourcePort, setSourcePort)}
                />
                {sourcePortError && <p className="text-xs leading-5 text-red-300">{sourcePortError}</p>}
              </Field>
            )}
            {useDestination && (
              <Field>
                <Label>Destination IPv4</Label>
                <input
                  className={inputClass(Boolean(destinationError), destination === firewallExamples.destination)}
                  value={destination}
                  onChange={(event) => setDestination(event.target.value)}
                  onFocus={() => clearExampleValue(destination, firewallExamples.destination, setDestination)}
                  onBlur={() => restoreExampleValue(destination, firewallExamples.destination, setDestination)}
                />
                {destinationError && <p className="text-xs leading-5 text-red-300">{destinationError}</p>}
              </Field>
            )}
            {protocol !== 'icmp' && (
              <Field>
                <Label>Destination port</Label>
                <input
                  className={inputClass(Boolean(portError), isPortExample && port === firewallExamples.destinationPort)}
                  value={port}
                  onChange={(event) => {
                    setPort(event.target.value);
                    setIsPortExample(false);
                  }}
                  onFocus={() => {
                    clearExampleValue(port, firewallExamples.destinationPort, setPort);
                    setIsPortExample(false);
                  }}
                  onBlur={() => {
                    if (!port.trim()) {
                      setPort(firewallExamples.destinationPort);
                      setIsPortExample(true);
                    }
                  }}
                />
                {portError && <p className="text-xs leading-5 text-red-300">{portError}</p>}
              </Field>
            )}
            <Field>
              <Label>Protocol</Label>
              <select className={inputClass()} value={protocol} onChange={(event) => setProtocol(event.target.value)}>
                <option>tcp</option>
                <option>udp</option>
                <option>icmp</option>
              </select>
            </Field>
          </div>
          {protocol !== 'icmp' && (
            <label className="mt-4 flex items-center gap-3 text-sm font-medium text-zinc-300">
              <input
                checked={useSourcePort}
                className="size-4 accent-emerald-500"
                type="checkbox"
                onChange={(event) => setUseSourcePort(event.target.checked)}
              />
              Add source port
            </label>
          )}
          <label className="mt-4 flex items-center gap-3 text-sm font-medium text-zinc-300">
            <input
              checked={useDestination}
              className="size-4 accent-emerald-500"
              type="checkbox"
              onChange={(event) => setUseDestination(event.target.checked)}
            />
            Add destination IPv4
          </label>
          {protocol === 'icmp' && (
            <div className="mt-4 rounded-2xl border border-yellow-400/30 bg-yellow-400/10 p-4 text-sm font-medium leading-6 text-yellow-200">
              Warning: UFW ICMP behavior can depend on distro defaults and before-rules. Test this command on your target system.
            </div>
          )}
          {sourceError || sourcePortError || portError || destinationError ? (
            <div className="mt-4 rounded-2xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-100">
              Fix the IPv4 address, CIDR prefix, or port before using the generated command.
            </div>
          ) : (
            <CommandBlock>{command}</CommandBlock>
          )}
        </div>
        {protocol !== 'icmp' && (
          <CommonPortsHint
            onSelectPort={(selectedPort) => {
              setPort(selectedPort);
              setIsPortExample(false);
            }}
          />
        )}
      </div>
    </Panel>
  );
}

function NftablesGenerator() {
  const [source, setSource] = useState(firewallExamples.source);
  const [useSourcePort, setUseSourcePort] = useState(false);
  const [sourcePort, setSourcePort] = useState(firewallExamples.sourcePort);
  const [useDestination, setUseDestination] = useState(false);
  const [destination, setDestination] = useState(firewallExamples.destination);
  const [port, setPort] = useState(firewallExamples.destinationPort);
  const [isPortExample, setIsPortExample] = useState(true);
  const [protocol, setProtocol] = useState('tcp');
  const [chain, setChain] = useState('input');
  const [action, setAction] = useState('accept');
  const sourceError = validateIpv4Cidr(source);
  const sourcePortError = protocol !== 'icmp' && useSourcePort ? validatePort(sourcePort) : null;
  const destinationError = useDestination ? validateIpv4Cidr(destination) : null;
  const portError = protocol !== 'icmp' ? validatePort(port) : null;
  const destinationClause = useDestination ? ` ip daddr ${destination}` : '';
  const sourcePortClause = protocol !== 'icmp' && useSourcePort ? ` ${protocol} sport ${sourcePort}` : '';
  const portClause = protocol === 'icmp' ? ' icmp type echo-request' : `${sourcePortClause} ${protocol} dport ${port}`;
  const command = `sudo nft add rule inet filter ${chain} ip saddr ${source}${destinationClause}${portClause} ${action}`;

  return (
    <Panel title="nftables generator">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Generate nftables rule commands for a common inet filter table. This assumes a table named
        <span className="font-mono text-zinc-100"> inet filter</span> and an existing input/forward/output chain.
      </p>
      <div className="mt-5 grid gap-6 xl:grid-cols-[minmax(0,1fr)_220px]">
        <div>
          <div className="grid gap-4 sm:grid-cols-3">
            <Field>
              <Label>Source IPv4</Label>
              <input
                className={inputClass(Boolean(sourceError), source === firewallExamples.source)}
                value={source}
                onChange={(event) => setSource(event.target.value)}
                onFocus={() => clearExampleValue(source, firewallExamples.source, setSource)}
                onBlur={() => restoreExampleValue(source, firewallExamples.source, setSource)}
              />
              {sourceError && <p className="text-xs leading-5 text-red-300">{sourceError}</p>}
            </Field>
            {protocol !== 'icmp' && useSourcePort && (
              <Field>
                <Label>Source port</Label>
                <input
                  className={inputClass(Boolean(sourcePortError), sourcePort === firewallExamples.sourcePort)}
                  value={sourcePort}
                  onChange={(event) => setSourcePort(event.target.value)}
                  onFocus={() => clearExampleValue(sourcePort, firewallExamples.sourcePort, setSourcePort)}
                  onBlur={() => restoreExampleValue(sourcePort, firewallExamples.sourcePort, setSourcePort)}
                />
                {sourcePortError && <p className="text-xs leading-5 text-red-300">{sourcePortError}</p>}
              </Field>
            )}
            {useDestination && (
              <Field>
                <Label>Destination IPv4</Label>
                <input
                  className={inputClass(Boolean(destinationError), destination === firewallExamples.destination)}
                  value={destination}
                  onChange={(event) => setDestination(event.target.value)}
                  onFocus={() => clearExampleValue(destination, firewallExamples.destination, setDestination)}
                  onBlur={() => restoreExampleValue(destination, firewallExamples.destination, setDestination)}
                />
                {destinationError && <p className="text-xs leading-5 text-red-300">{destinationError}</p>}
              </Field>
            )}
            {protocol !== 'icmp' && (
              <Field>
                <Label>Destination port</Label>
                <input
                  className={inputClass(Boolean(portError), isPortExample && port === firewallExamples.destinationPort)}
                  value={port}
                  onChange={(event) => {
                    setPort(event.target.value);
                    setIsPortExample(false);
                  }}
                  onFocus={() => {
                    clearExampleValue(port, firewallExamples.destinationPort, setPort);
                    setIsPortExample(false);
                  }}
                  onBlur={() => {
                    if (!port.trim()) {
                      setPort(firewallExamples.destinationPort);
                      setIsPortExample(true);
                    }
                  }}
                />
                {portError && <p className="text-xs leading-5 text-red-300">{portError}</p>}
              </Field>
            )}
            <Field>
              <Label>Protocol</Label>
              <select className={inputClass()} value={protocol} onChange={(event) => setProtocol(event.target.value)}>
                <option>tcp</option>
                <option>udp</option>
                <option>icmp</option>
              </select>
            </Field>
            <Field>
              <Label>Chain</Label>
              <select className={inputClass()} value={chain} onChange={(event) => setChain(event.target.value)}>
                <option>input</option>
                <option>forward</option>
                <option>output</option>
              </select>
            </Field>
            <Field>
              <Label>Action</Label>
              <select className={inputClass()} value={action} onChange={(event) => setAction(event.target.value)}>
                <option>accept</option>
                <option>drop</option>
                <option>reject</option>
              </select>
            </Field>
          </div>
          {protocol !== 'icmp' && (
            <label className="mt-4 flex items-center gap-3 text-sm font-medium text-zinc-300">
              <input
                checked={useSourcePort}
                className="size-4 accent-emerald-500"
                type="checkbox"
                onChange={(event) => setUseSourcePort(event.target.checked)}
              />
              Add source port
            </label>
          )}
          <label className="mt-4 flex items-center gap-3 text-sm font-medium text-zinc-300">
            <input
              checked={useDestination}
              className="size-4 accent-emerald-500"
              type="checkbox"
              onChange={(event) => setUseDestination(event.target.checked)}
            />
            Add destination IPv4
          </label>
          {sourceError || sourcePortError || destinationError || portError ? (
            <div className="mt-4 rounded-2xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-100">
              Fix the IPv4 address, CIDR prefix, or port before using the generated command.
            </div>
          ) : (
            <CommandBlock>{command}</CommandBlock>
          )}
        </div>
        {protocol !== 'icmp' && (
          <CommonPortsHint
            onSelectPort={(selectedPort) => {
              setPort(selectedPort);
              setIsPortExample(false);
            }}
          />
        )}
      </div>
    </Panel>
  );
}

function FirewalldGenerator() {
  const [source, setSource] = useState(firewallExamples.source);
  const [useSourcePort, setUseSourcePort] = useState(false);
  const [sourcePort, setSourcePort] = useState(firewallExamples.sourcePort);
  const [useDestination, setUseDestination] = useState(false);
  const [destination, setDestination] = useState(firewallExamples.destination);
  const [port, setPort] = useState(firewallExamples.destinationPort);
  const [isPortExample, setIsPortExample] = useState(true);
  const [protocol, setProtocol] = useState('tcp');
  const [mode, setMode] = useState<'runtime' | 'permanent'>('permanent');
  const sourceError = validateIpv4Cidr(source);
  const sourcePortError = protocol !== 'icmp' && useSourcePort ? validatePort(sourcePort) : null;
  const portError = protocol !== 'icmp' ? validatePort(port) : null;
  const destinationError = useDestination ? validateIpv4Cidr(destination) : null;
  const sourcePortClause =
    protocol !== 'icmp' && useSourcePort ? ` source-port port="${sourcePort}" protocol="${protocol}"` : '';
  const destinationClause = useDestination ? ` destination address="${destination}"` : '';
  const command =
    protocol === 'icmp'
      ? `sudo firewall-cmd ${
          mode === 'permanent' ? '--permanent ' : ''
        }--add-rich-rule='rule family="ipv4" source address="${source}"${destinationClause} protocol value="icmp" accept'`
      : `sudo firewall-cmd ${
          mode === 'permanent' ? '--permanent ' : ''
        }--add-rich-rule='rule family="ipv4" source address="${source}"${destinationClause}${sourcePortClause} port port="${port}" protocol="${protocol}" accept'`;

  return (
    <div className="space-y-6">
      <Panel title="Firewalld rich-rule generator">
        <p className="max-w-4xl text-sm leading-6 text-zinc-300">
          Firewalld rich rules provide a more expressive and granular way to define custom firewall policies than basic
          zone-based rules. While standard rules typically apply to all traffic in a zone, rich rules allow you to combine
          specific source/destination addresses, logging, and rate limiting in a single statement.
        </p>
        <div className="mt-5 grid gap-6 xl:grid-cols-[minmax(0,1fr)_220px]">
          <div>
            <div className="grid gap-4 sm:grid-cols-3">
              <Field>
                <Label>Source IPv4</Label>
                <input
                  className={inputClass(Boolean(sourceError), source === firewallExamples.source)}
                  value={source}
                  onChange={(event) => setSource(event.target.value)}
                  onFocus={() => clearExampleValue(source, firewallExamples.source, setSource)}
                  onBlur={() => restoreExampleValue(source, firewallExamples.source, setSource)}
                />
                {sourceError && <p className="text-xs leading-5 text-red-300">{sourceError}</p>}
              </Field>
              {protocol !== 'icmp' && useSourcePort && (
                <Field>
                  <Label>Source port</Label>
                  <input
                    className={inputClass(Boolean(sourcePortError), sourcePort === firewallExamples.sourcePort)}
                    value={sourcePort}
                    onChange={(event) => setSourcePort(event.target.value)}
                    onFocus={() => clearExampleValue(sourcePort, firewallExamples.sourcePort, setSourcePort)}
                    onBlur={() => restoreExampleValue(sourcePort, firewallExamples.sourcePort, setSourcePort)}
                  />
                  {sourcePortError && <p className="text-xs leading-5 text-red-300">{sourcePortError}</p>}
                </Field>
              )}
              {useDestination && (
                <Field>
                  <Label>Destination IPv4</Label>
                  <input
                    className={inputClass(Boolean(destinationError), destination === firewallExamples.destination)}
                    value={destination}
                    onChange={(event) => setDestination(event.target.value)}
                    onFocus={() => clearExampleValue(destination, firewallExamples.destination, setDestination)}
                    onBlur={() => restoreExampleValue(destination, firewallExamples.destination, setDestination)}
                  />
                  {destinationError && <p className="text-xs leading-5 text-red-300">{destinationError}</p>}
                </Field>
              )}
              {protocol !== 'icmp' && (
                <Field>
                  <Label>Destination port</Label>
                  <input
                    className={inputClass(Boolean(portError), isPortExample && port === firewallExamples.destinationPort)}
                    value={port}
                    onChange={(event) => {
                      setPort(event.target.value);
                      setIsPortExample(false);
                    }}
                    onFocus={() => {
                      clearExampleValue(port, firewallExamples.destinationPort, setPort);
                      setIsPortExample(false);
                    }}
                    onBlur={() => {
                      if (!port.trim()) {
                        setPort(firewallExamples.destinationPort);
                        setIsPortExample(true);
                      }
                    }}
                  />
                  {portError && <p className="text-xs leading-5 text-red-300">{portError}</p>}
                </Field>
              )}
              <Field>
                <Label>Protocol</Label>
                <select className={inputClass()} value={protocol} onChange={(event) => setProtocol(event.target.value)}>
                  <option>tcp</option>
                  <option>udp</option>
                  <option>icmp</option>
                </select>
              </Field>
              <Field>
                <Label>Rule mode</Label>
                <select
                  className={inputClass()}
                  value={mode}
                  onChange={(event) => setMode(event.target.value as 'runtime' | 'permanent')}
                >
                  <option value="permanent">Permanent</option>
                  <option value="runtime">Runtime</option>
                </select>
              </Field>
            </div>
            <div className="mt-4 rounded-2xl border border-emerald-500/15 bg-emerald-500/10 p-4 text-sm leading-6 text-zinc-300">
              <span className="font-semibold text-zinc-100">Rule mode</span> controls the generated rich-rule command below.
              <span className="font-semibold text-emerald-300"> Permanent</span> saves the rule in firewalld config and needs
              reload to apply. <span className="font-semibold text-emerald-300">Runtime</span> applies now but is lost after
              firewalld reload or restart.
            </div>
            {protocol !== 'icmp' && (
              <label className="mt-4 flex items-center gap-3 text-sm font-medium text-zinc-300">
                <input
                  checked={useSourcePort}
                  className="size-4 accent-emerald-500"
                  type="checkbox"
                  onChange={(event) => setUseSourcePort(event.target.checked)}
                />
                Add source port
              </label>
            )}
            <label className="mt-4 flex items-center gap-3 text-sm font-medium text-zinc-300">
              <input
                checked={useDestination}
                className="size-4 accent-emerald-500"
                type="checkbox"
                onChange={(event) => setUseDestination(event.target.checked)}
              />
              Add destination IPv4
            </label>
            {sourceError || sourcePortError || portError || destinationError ? (
              <div className="mt-4 rounded-2xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-100">
                Fix the IPv4 address, CIDR prefix, or port before using the generated command.
              </div>
            ) : (
              <>
                <CommandBlock>{command}</CommandBlock>
                {mode === 'permanent' && <CommandBlock>sudo firewall-cmd --reload</CommandBlock>}
              </>
            )}
          </div>
          {protocol !== 'icmp' && (
            <CommonPortsHint
              onSelectPort={(selectedPort) => {
                setPort(selectedPort);
                setIsPortExample(false);
              }}
            />
          )}
        </div>
      </Panel>
      <FirewalldZonesBlock />
    </div>
  );
}

function FirewalldZonesBlock() {
  const [useCustomZone, setUseCustomZone] = useState(false);
  const [zonePreset, setZonePreset] = useState('public');
  const [customZone, setCustomZone] = useState('app-zone');
  const [mode, setMode] = useState<'runtime' | 'permanent'>('permanent');
  const [useSource, setUseSource] = useState(false);
  const [source, setSource] = useState(firewallExamples.source);
  const [useService, setUseService] = useState(false);
  const [service, setService] = useState('ssh');
  const [usePort, setUsePort] = useState(false);
  const [port, setPort] = useState(firewallExamples.destinationPort);
  const [protocol, setProtocol] = useState('tcp');
  const [useIcmp, setUseIcmp] = useState(false);
  const [icmpAction, setIcmpAction] = useState<'allow' | 'block'>('allow');
  const zone = useCustomZone ? customZone.trim() : zonePreset;
  const zoneError = useCustomZone ? validateZoneName(customZone) : null;
  const sourceError = useSource ? validateIpv4Cidr(source) : null;
  const portError = usePort ? validatePort(port) : null;
  const modeFlag = mode === 'permanent' ? '--permanent ' : '';
  const createZoneCommand = `sudo firewall-cmd --permanent --new-zone=${zone}`;
  const listZoneCommand = `sudo firewall-cmd --zone=${zone} --list-all`;
  const activeZonesCommand = 'sudo firewall-cmd --get-active-zones';
  const addSourceCommand = `sudo firewall-cmd ${modeFlag}--zone=${zone} --add-source=${source}`;
  const addServiceCommand = `sudo firewall-cmd ${modeFlag}--zone=${zone} --add-service=${service}`;
  const addPortCommand = `sudo firewall-cmd ${modeFlag}--zone=${zone} --add-port=${port}/${protocol}`;
  const icmpCommand = `sudo firewall-cmd ${modeFlag}--zone=${zone} ${
    icmpAction === 'allow' ? '--remove-icmp-block=echo-request' : '--add-icmp-block=echo-request'
  }`;

  return (
    <Panel title="Firewalld zones">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Firewalld zones are essentially trust levels for network connections. Instead of managing a single massive list of
        rules, you assign network interfaces or source IP addresses to a zone that has its own predefined set of allowed
        services and ports.
      </p>
      <div className="mt-4 rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
        <h3 className="text-sm font-semibold text-zinc-200">Zone idea</h3>
        <p className="mt-3 text-sm leading-6 text-zinc-400">
          Use zones to group trust levels first, then use rich rules only when you need more specific matching than a
          normal zone service or port rule can express.
        </p>
      </div>
      <div className="mt-5 grid gap-6 xl:grid-cols-[minmax(0,1fr)_220px]">
        <div>
          <div className="mb-4 flex flex-wrap gap-2">
            <button
              className={`rounded-lg border px-3 py-2 text-sm font-semibold transition ${
                !useCustomZone
                  ? 'border-emerald-400/50 bg-emerald-500/10 text-emerald-300'
                  : 'border-white/10 text-zinc-300 hover:border-emerald-400/40'
              }`}
              type="button"
              onClick={() => setUseCustomZone(false)}
            >
              Predefined zone
            </button>
            <button
              className={`rounded-lg border px-3 py-2 text-sm font-semibold transition ${
                useCustomZone
                  ? 'border-emerald-400/50 bg-emerald-500/10 text-emerald-300'
                  : 'border-white/10 text-zinc-300 hover:border-emerald-400/40'
              }`}
              type="button"
              onClick={() => setUseCustomZone(true)}
            >
              Custom zone
            </button>
          </div>
          <div className="grid gap-4 sm:grid-cols-3">
            {!useCustomZone && (
              <Field>
                <Label>Predefined zone</Label>
                <select className={inputClass()} value={zonePreset} onChange={(event) => setZonePreset(event.target.value)}>
                  {firewalldZones.map((zoneName) => (
                    <option key={zoneName} value={zoneName}>
                      {zoneName}
                    </option>
                  ))}
                </select>
              </Field>
            )}
            {useCustomZone && (
              <Field>
                <Label>Custom zone name</Label>
                <input
                  className={inputClass(Boolean(zoneError), customZone === 'app-zone')}
                  value={customZone}
                  onChange={(event) => setCustomZone(event.target.value)}
                  onFocus={() => clearExampleValue(customZone, 'app-zone', setCustomZone)}
                  onBlur={() => restoreExampleValue(customZone, 'app-zone', setCustomZone)}
                />
                {zoneError && <p className="text-xs leading-5 text-red-300">{zoneError}</p>}
              </Field>
            )}
            <Field>
              <Label>Zone mode</Label>
              <select
                className={inputClass()}
                value={mode}
                onChange={(event) => setMode(event.target.value as 'runtime' | 'permanent')}
              >
                <option value="permanent">Permanent</option>
                <option value="runtime">Runtime</option>
              </select>
            </Field>
            {useSource && (
              <Field>
                <Label>Source IPv4</Label>
                <input
                  className={inputClass(Boolean(sourceError), source === firewallExamples.source)}
                  value={source}
                  onChange={(event) => setSource(event.target.value)}
                  onFocus={() => clearExampleValue(source, firewallExamples.source, setSource)}
                  onBlur={() => restoreExampleValue(source, firewallExamples.source, setSource)}
                />
                {sourceError && <p className="text-xs leading-5 text-red-300">{sourceError}</p>}
              </Field>
            )}
            {useService && (
              <Field>
                <Label>Service</Label>
                <select className={inputClass()} value={service} onChange={(event) => setService(event.target.value)}>
                  {commonFirewalldServices.map((serviceName) => (
                    <option key={serviceName} value={serviceName}>
                      {serviceName}
                    </option>
                  ))}
                </select>
              </Field>
            )}
            {usePort && (
              <>
                <Field>
                  <Label>Destination port</Label>
                  <input
                    className={inputClass(Boolean(portError), port === firewallExamples.destinationPort)}
                    value={port}
                    onChange={(event) => setPort(event.target.value)}
                    onFocus={() => clearExampleValue(port, firewallExamples.destinationPort, setPort)}
                    onBlur={() => restoreExampleValue(port, firewallExamples.destinationPort, setPort)}
                  />
                  {portError && <p className="text-xs leading-5 text-red-300">{portError}</p>}
                </Field>
                <Field>
                  <Label>Protocol</Label>
                  <select className={inputClass()} value={protocol} onChange={(event) => setProtocol(event.target.value)}>
                    <option>tcp</option>
                    <option>udp</option>
                  </select>
                </Field>
              </>
            )}
            {useIcmp && (
              <Field>
                <Label>ICMP action</Label>
                <select
                  className={inputClass()}
                  value={icmpAction}
                  onChange={(event) => setIcmpAction(event.target.value as 'allow' | 'block')}
                >
                  <option value="allow">Allow ping</option>
                  <option value="block">Block ping</option>
                </select>
              </Field>
            )}
          </div>
          <div className="mt-4 grid gap-3 sm:grid-cols-3">
            <label className="flex items-center gap-3 text-sm font-medium text-zinc-300">
              <input
                checked={useSource}
                className="size-4 accent-emerald-500"
                type="checkbox"
                onChange={(event) => setUseSource(event.target.checked)}
              />
              Add source IPv4
            </label>
            <label className="flex items-center gap-3 text-sm font-medium text-zinc-300">
              <input
                checked={useService}
                className="size-4 accent-emerald-500"
                type="checkbox"
                onChange={(event) => {
                  setUseService(event.target.checked);

                  if (event.target.checked) {
                    setUsePort(false);
                    setUseIcmp(false);
                  }
                }}
              />
              Add service
            </label>
            <label className="flex items-center gap-3 text-sm font-medium text-zinc-300">
              <input
                checked={usePort}
                className="size-4 accent-emerald-500"
                type="checkbox"
                onChange={(event) => {
                  setUsePort(event.target.checked);

                  if (event.target.checked) {
                    setUseService(false);
                    setUseIcmp(false);
                  }
                }}
              />
              Add destination port
            </label>
            <label className="flex items-center gap-3 text-sm font-medium text-zinc-300">
              <input
                checked={useIcmp}
                className="size-4 accent-emerald-500"
                type="checkbox"
                onChange={(event) => {
                  setUseIcmp(event.target.checked);

                  if (event.target.checked) {
                    setUseService(false);
                    setUsePort(false);
                  }
                }}
              />
              Configure ICMP
              <HelpTooltip text="Controls ping for this zone. Allow ping removes the echo-request ICMP block. Block ping adds the echo-request ICMP block." />
            </label>
          </div>
          <div className="mt-4 rounded-2xl border border-emerald-500/15 bg-emerald-500/10 p-4 text-sm leading-6 text-zinc-300">
            <span className="font-semibold text-zinc-100">Zone mode</span> controls the generated zone commands below.
            <span className="font-semibold text-emerald-300"> Permanent</span> saves zone changes in firewalld config and
            usually needs reload. <span className="font-semibold text-emerald-300">Runtime</span> applies now but is lost
            after firewalld reload or restart.
          </div>
          {zoneError || sourceError || portError ? (
            <div className="mt-4 rounded-2xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-100">
              Fix the zone name, IPv4 source, or port before using the generated command.
            </div>
          ) : (
            <>
              {useCustomZone && (
                <div className="mt-4 rounded-2xl border border-yellow-400/20 bg-yellow-400/10 p-4">
                  <h3 className="text-sm font-semibold text-yellow-200">Create custom zone if missing</h3>
                  <p className="mt-2 text-sm leading-6 text-yellow-100/80">
                    These two commands create the zone and reload firewalld so the new zone becomes available.
                  </p>
                  <CommandBlock>{createZoneCommand}</CommandBlock>
                  <CommandBlock>sudo firewall-cmd --reload</CommandBlock>
                </div>
              )}
              {useSource && <CommandBlock>{addSourceCommand}</CommandBlock>}
              {useService && <CommandBlock>{addServiceCommand}</CommandBlock>}
              {usePort && <CommandBlock>{addPortCommand}</CommandBlock>}
              {useIcmp && <CommandBlock>{icmpCommand}</CommandBlock>}
              <CommandBlock>{listZoneCommand}</CommandBlock>
              <CommandBlock>{activeZonesCommand}</CommandBlock>
            </>
          )}
        </div>
        {usePort && (
          <CommonPortsHint
            onSelectPort={(selectedPort) => {
              setPort(selectedPort);
            }}
          />
        )}
      </div>
    </Panel>
  );
}

type PermissionGroup = 'owner' | 'group' | 'others';
type PermissionBit = 'read' | 'write' | 'execute';

const permissionValues: Record<PermissionBit, number> = {
  read: 4,
  write: 2,
  execute: 1,
};

const permissionLabels: Record<PermissionBit, string> = {
  read: 'Read',
  write: 'Write',
  execute: 'Execute',
};

function ChmodCalculator() {
  const [path, setPath] = useState('/var/www/html');
  const [permissions, setPermissions] = useState<Record<PermissionGroup, Record<PermissionBit, boolean>>>({
    owner: { read: true, write: true, execute: true },
    group: { read: true, write: false, execute: true },
    others: { read: true, write: false, execute: true },
  });

  function togglePermission(group: PermissionGroup, bit: PermissionBit) {
    setPermissions((current) => ({
      ...current,
      [group]: {
        ...current[group],
        [bit]: !current[group][bit],
      },
    }));
  }

  function groupValue(group: PermissionGroup) {
    return (Object.keys(permissionValues) as PermissionBit[]).reduce((total, bit) => {
      return permissions[group][bit] ? total + permissionValues[bit] : total;
    }, 0);
  }

  const mode = `${groupValue('owner')}${groupValue('group')}${groupValue('others')}`;
  const command = `chmod ${mode} ${path || '<path>'}`;

  return (
    <Panel title="chmod calculator">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Choose read, write, and execute permissions for owner, group, and others to generate a numeric chmod command.
      </p>
      <div className="mt-5 grid gap-4 lg:grid-cols-[minmax(0,1fr)_240px]">
        <div>
          <Field>
            <Label>Path</Label>
            <input
              className={inputClass(false, path === '/var/www/html')}
              value={path}
              onChange={(event) => setPath(event.target.value)}
              onFocus={() => clearExampleValue(path, '/var/www/html', setPath)}
              onBlur={() => restoreExampleValue(path, '/var/www/html', setPath)}
            />
          </Field>
          <div className="mt-5 grid gap-4 md:grid-cols-3">
            {(['owner', 'group', 'others'] as PermissionGroup[]).map((group) => (
              <div key={group} className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
                <h3 className="text-sm font-semibold capitalize text-zinc-200">{group}</h3>
                <div className="mt-4 space-y-3">
                  {(['read', 'write', 'execute'] as PermissionBit[]).map((bit) => (
                    <label key={bit} className="flex items-center gap-3 text-sm text-zinc-300">
                      <input
                        checked={permissions[group][bit]}
                        className="size-4 accent-emerald-500"
                        type="checkbox"
                        onChange={() => togglePermission(group, bit)}
                      />
                      {permissionLabels[bit]}
                    </label>
                  ))}
                </div>
                <p className="mt-4 rounded-lg bg-emerald-500/10 px-3 py-2 text-sm font-semibold text-emerald-300">
                  {groupValue(group)}
                </p>
              </div>
            ))}
          </div>
          <CommandBlock>{command}</CommandBlock>
        </div>
        <aside className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <h3 className="text-sm font-semibold text-zinc-200">Permission values</h3>
          <div className="mt-3 space-y-2 text-sm text-zinc-400">
            <p>Read = 4</p>
            <p>Write = 2</p>
            <p>Execute = 1</p>
          </div>
          <p className="mt-4 text-sm leading-6 text-zinc-400">
            Each column adds up to one digit. For example, read + execute is 5.
          </p>
        </aside>
      </div>
    </Panel>
  );
}

const cronPresets = [
  { label: 'Every 5 minutes', value: 'every-5-minutes', fields: ['*/5', '*', '*', '*', '*'] },
  { label: 'Every 15 minutes', value: 'every-15-minutes', fields: ['*/15', '*', '*', '*', '*'] },
  { label: 'Every 30 minutes', value: 'every-30-minutes', fields: ['*/30', '*', '*', '*', '*'] },
  { label: 'Hourly', value: 'hourly', fields: ['0', '*', '*', '*', '*'] },
  { label: 'Every 4 hours', value: 'every-4-hours', fields: ['0', '*/4', '*', '*', '*'] },
  { label: 'Every 8 hours', value: 'every-8-hours', fields: ['0', '*/8', '*', '*', '*'] },
  { label: 'Daily at midnight', value: 'daily-midnight', fields: ['0', '0', '*', '*', '*'] },
  { label: 'Daily at 02:00', value: 'daily-2', fields: ['0', '2', '*', '*', '*'] },
  { label: 'Weekly on Sunday', value: 'weekly-sunday', fields: ['0', '0', '*', '*', '0'] },
  { label: 'Monthly on the 1st', value: 'monthly-first', fields: ['0', '0', '1', '*', '*'] },
];

const cronFieldLabels = ['Minute', 'Hour', 'Day of month', 'Month', 'Day of week'];
const cronFieldRanges = [
  { min: 0, max: 59 },
  { min: 0, max: 23 },
  { min: 1, max: 31 },
  { min: 1, max: 12 },
  { min: 0, max: 7 },
];

function validateCronField(value: string, min: number, max: number, label: string) {
  const trimmedValue = value.trim();

  if (!trimmedValue) {
    return `${label} is required. Use a value between ${min} and ${max}, or * for every value.`;
  }

  if (trimmedValue === '*') {
    return null;
  }

  const parts = trimmedValue.split(',');

  for (const part of parts) {
    const [rangePart, stepPart, extraStep] = part.split('/');

    if (!rangePart || extraStep !== undefined) {
      return 'Use values like *, */5, 1, 1-5, or 1-10/2.';
    }

    if (stepPart !== undefined && (!/^\d+$/.test(stepPart) || Number(stepPart) < 1)) {
      return 'Step must be a positive number.';
    }

    if (rangePart === '*') {
      continue;
    }

    const rangeValues = rangePart.split('-');

    if (rangeValues.length > 2 || rangeValues.some((rangeValue) => !/^\d+$/.test(rangeValue))) {
      return 'Use numbers, ranges, lists, wildcards, or steps.';
    }

    const start = Number(rangeValues[0]);
    const end = rangeValues.length === 2 ? Number(rangeValues[1]) : start;

    if (start < min || start > max || end < min || end > max) {
      return `Allowed range is ${min}-${max}.`;
    }

    if (start > end) {
      return 'Range start must be smaller than range end.';
    }
  }

  return null;
}

function CronGenerator() {
  const commandExample = '/usr/local/bin/backup.sh';
  const [useCustomSchedule, setUseCustomSchedule] = useState(false);
  const [preset, setPreset] = useState('daily-2');
  const [fields, setFields] = useState(['0', '2', '*', '*', '*']);
  const [command, setCommand] = useState(commandExample);
  const fieldErrors = fields.map((field, index) =>
    validateCronField(field, cronFieldRanges[index].min, cronFieldRanges[index].max, cronFieldLabels[index]),
  );
  const hasErrors = fieldErrors.some(Boolean);
  const crontabLine = `${fields.join(' ')} ${command || '<command>'}`;

  function selectPreset(nextPreset: string) {
    setPreset(nextPreset);
    const selectedPreset = cronPresets.find((cronPreset) => cronPreset.value === nextPreset);

    if (selectedPreset) {
      setFields(selectedPreset.fields);
    }
  }

  function updateField(index: number, value: string) {
    setUseCustomSchedule(true);
    setFields((currentFields) => currentFields.map((field, fieldIndex) => (fieldIndex === index ? value : field)));
  }

  return (
    <Panel title="Cron generator">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Build a crontab line from common presets or edit the five cron fields directly. Cron field order is minute, hour,
        day of month, month, day of week.
      </p>
      <div className="mt-5 grid gap-6 lg:grid-cols-[minmax(0,1fr)_260px]">
        <div>
          <div className="mb-4 flex flex-wrap gap-2">
            <button
              className={`rounded-lg border px-3 py-2 text-sm font-semibold transition ${
                !useCustomSchedule
                  ? 'border-emerald-400/50 bg-emerald-500/10 text-emerald-300'
                  : 'border-white/10 text-zinc-300 hover:border-emerald-400/40'
              }`}
              type="button"
              onClick={() => {
                setUseCustomSchedule(false);
                selectPreset(preset);
              }}
            >
              Preset schedule
            </button>
            <button
              className={`rounded-lg border px-3 py-2 text-sm font-semibold transition ${
                useCustomSchedule
                  ? 'border-emerald-400/50 bg-emerald-500/10 text-emerald-300'
                  : 'border-white/10 text-zinc-300 hover:border-emerald-400/40'
              }`}
              type="button"
              onClick={() => setUseCustomSchedule(true)}
            >
              Custom schedule
            </button>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            {!useCustomSchedule && (
              <Field>
                <Label>Schedule preset</Label>
                <select className={inputClass()} value={preset} onChange={(event) => selectPreset(event.target.value)}>
                  {cronPresets.map((cronPreset) => (
                    <option key={cronPreset.value} value={cronPreset.value}>
                      {cronPreset.label}
                    </option>
                  ))}
                </select>
              </Field>
            )}
            <Field>
              <Label>Command</Label>
              <input
                className={inputClass(false, command === commandExample)}
                value={command}
                onChange={(event) => setCommand(event.target.value)}
                onFocus={() => clearExampleValue(command, commandExample, setCommand)}
                onBlur={() => restoreExampleValue(command, commandExample, setCommand)}
              />
            </Field>
          </div>
          {useCustomSchedule && (
            <div className="mt-5 grid gap-4 sm:grid-cols-5">
              {fields.map((field, index) => (
                <Field key={cronFieldLabels[index]}>
                  <Label>{cronFieldLabels[index]}</Label>
                  <input
                    className={inputClass(Boolean(fieldErrors[index]))}
                    value={field}
                    onChange={(event) => updateField(index, event.target.value)}
                  />
                  {fieldErrors[index] && <p className="text-xs leading-5 text-red-300">{fieldErrors[index]}</p>}
                </Field>
              ))}
            </div>
          )}
          {hasErrors ? (
            <div className="mt-4 rounded-2xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-100">
              Fix the cron field values before using the generated crontab line.
            </div>
          ) : (
            <CommandBlock>{crontabLine}</CommandBlock>
          )}
        </div>
        <aside className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <h3 className="text-sm font-semibold text-zinc-200">Cron symbols</h3>
          <div className="mt-3 space-y-2 text-sm text-zinc-400">
            <p><span className="font-mono text-zinc-300">*</span> every value</p>
            <p><span className="font-mono text-zinc-300">*/5</span> every 5 units</p>
            <p><span className="font-mono text-zinc-300">1,15</span> list of values</p>
            <p><span className="font-mono text-zinc-300">1-5</span> range</p>
          </div>
        </aside>
      </div>
    </Panel>
  );
}

function JsonFormatter() {
  const sample = '{"name":"it-toolbox","status":"test","tools":["dns","ufw","json"]}';
  const [input, setInput] = useState(sample);
  const [indentSize, setIndentSize] = useState('2');
  let formatted = '';
  let error = '';

  try {
    formatted = JSON.stringify(JSON.parse(input), null, Number(indentSize));
  } catch (caughtError) {
    error = caughtError instanceof Error ? caughtError.message : 'Invalid JSON.';
  }

  return (
    <Panel title="JSON formatter">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Paste JSON here to validate it and produce a readable formatted version. The formatter runs locally in the browser.
      </p>
      <div className="mt-5 grid gap-4 sm:grid-cols-[1fr_160px]">
        <Field>
          <Label>Input</Label>
          <textarea
            className={`${inputClass(Boolean(error), input === sample)} min-h-44 font-mono`}
            value={input}
            onChange={(event) => setInput(event.target.value)}
            onFocus={() => clearExampleValue(input, sample, setInput)}
            onBlur={() => {
              if (!input.trim()) {
                setInput(sample);
              }
            }}
          />
          {error && <p className="text-xs leading-5 text-red-300">{error}</p>}
        </Field>
        <Field>
          <Label>Indent</Label>
          <select className={inputClass()} value={indentSize} onChange={(event) => setIndentSize(event.target.value)}>
            <option value="2">2 spaces</option>
            <option value="4">4 spaces</option>
          </select>
        </Field>
      </div>
      {error ? (
        <div className="mt-4 rounded-2xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-100">
          Fix the JSON syntax before using the formatted output.
        </div>
      ) : (
        <CommandBlock>{formatted}</CommandBlock>
      )}
    </Panel>
  );
}

function formatYamlLite(value: string) {
  const lines = value.replace(/\r\n?/g, '\n').split('\n');

  if (lines.some((line) => line.includes('\t'))) {
    return { output: '', error: 'YAML indentation should use spaces, not tabs.' };
  }

  const trimmedLines = lines.map((line) => line.replace(/\s+$/g, ''));
  const firstContentIndex = trimmedLines.findIndex((line) => line.trim());
  let lastContentIndex = -1;

  for (let index = trimmedLines.length - 1; index >= 0; index -= 1) {
    if (trimmedLines[index].trim()) {
      lastContentIndex = index;
      break;
    }
  }

  const contentLines =
    firstContentIndex === -1 ? [] : trimmedLines.slice(firstContentIndex, lastContentIndex + 1);

  for (const line of contentLines) {
    if (!line.trim() || line.trim().startsWith('#') || line.trim() === '---' || line.trim() === '...') {
      continue;
    }

    const leadingSpaces = line.length - line.trimStart().length;

    if (leadingSpaces % 2 !== 0) {
      return { output: '', error: 'YAML indentation should use consistent 2-space levels.' };
    }
  }

  const outputLines = contentLines.reduce<string[]>((accumulator, line) => {
    const isBlank = !line.trim();
    const previousIsBlank = accumulator.length > 0 && !accumulator[accumulator.length - 1].trim();

    if (isBlank && previousIsBlank) {
      return accumulator;
    }

    return [...accumulator, line];
  }, []);

  return { output: outputLines.join('\n'), error: '' };
}

function JsonYamlFormatter() {
  const jsonSample = '{"name":"it-toolbox","enabled":true,"tools":["json","yaml"]}';
  const yamlSample = 'name: it-toolbox\nenabled: true\ntools:\n  - json\n  - yaml';
  const [mode, setMode] = useState<'json' | 'yaml'>('json');
  const [input, setInput] = useState(jsonSample);
  const [indentSize, setIndentSize] = useState('2');
  const activeSample = mode === 'json' ? jsonSample : yamlSample;
  let formatted = '';
  let error = '';

  if (mode === 'json') {
    try {
      formatted = JSON.stringify(JSON.parse(input), null, Number(indentSize));
    } catch (caughtError) {
      error = caughtError instanceof Error ? caughtError.message : 'Invalid JSON.';
    }
  } else {
    const yamlResult = formatYamlLite(input);
    formatted = yamlResult.output;
    error = yamlResult.error;
  }

  function changeMode(nextMode: 'json' | 'yaml') {
    setMode(nextMode);
    setInput(nextMode === 'json' ? jsonSample : yamlSample);
  }

  return (
    <Panel title="JSON/YAML formatter">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Format JSON with full browser-side validation, or clean up common YAML snippets by trimming whitespace and checking
        indentation before copying the result.
      </p>
      <div className="mt-5 flex flex-wrap gap-2">
        <button
          className={`rounded-lg border px-3 py-2 text-sm font-semibold transition ${
            mode === 'json'
              ? 'border-emerald-400/50 bg-emerald-500/10 text-emerald-300'
              : 'border-white/10 text-zinc-300 hover:border-emerald-400/40'
          }`}
          type="button"
          onClick={() => changeMode('json')}
        >
          JSON
        </button>
        <button
          className={`rounded-lg border px-3 py-2 text-sm font-semibold transition ${
            mode === 'yaml'
              ? 'border-emerald-400/50 bg-emerald-500/10 text-emerald-300'
              : 'border-white/10 text-zinc-300 hover:border-emerald-400/40'
          }`}
          type="button"
          onClick={() => changeMode('yaml')}
        >
          YAML
        </button>
      </div>
      <div className="mt-5 grid gap-4 sm:grid-cols-[1fr_160px]">
        <Field>
          <Label>Input</Label>
          <textarea
            className={`${inputClass(Boolean(error), input === activeSample)} min-h-44 font-mono`}
            value={input}
            onChange={(event) => setInput(event.target.value)}
            onFocus={() => clearExampleValue(input, activeSample, setInput)}
            onBlur={() => restoreExampleValue(input, activeSample, setInput)}
          />
          {error && <p className="text-xs leading-5 text-red-300">{error}</p>}
        </Field>
        {mode === 'json' && (
          <Field>
            <Label>Indent</Label>
            <select className={inputClass()} value={indentSize} onChange={(event) => setIndentSize(event.target.value)}>
              <option value="2">2 spaces</option>
              <option value="4">4 spaces</option>
            </select>
          </Field>
        )}
      </div>
      {error ? (
        <div className="mt-4 rounded-2xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-100">
          Fix the {mode.toUpperCase()} input before using the formatted output.
        </div>
      ) : (
        <CommandBlock>{formatted}</CommandBlock>
      )}
    </Panel>
  );
}

type EncoderMode = 'base64-encode' | 'base64-decode' | 'url-encode' | 'url-decode';

function EncoderTool() {
  const encoderSamples: Record<EncoderMode, string> = {
    'base64-encode': 'Hello from IT Toolbox!',
    'base64-decode': 'SGVsbG8gZnJvbSBJVCBUb29sYm94IQ==',
    'url-encode': 'Hello from IT Toolbox!',
    'url-decode': 'Hello%20from%20IT%20Toolbox%21',
  };
  const [mode, setMode] = useState<EncoderMode>('base64-encode');
  const [input, setInput] = useState(encoderSamples['base64-encode']);
  const sample = encoderSamples[mode];
  let output = '';
  let error = '';

  try {
    if (mode === 'base64-encode') {
      output = btoa(unescape(encodeURIComponent(input)));
    } else if (mode === 'base64-decode') {
      output = decodeURIComponent(escape(atob(input.trim())));
    } else if (mode === 'url-encode') {
      output = encodeURIComponent(input);
    } else {
      output = decodeURIComponent(input);
    }
  } catch {
    error = mode === 'base64-decode' ? 'Input is not valid Base64.' : 'Input is not valid URL-encoded text.';
  }

  return (
    <Panel title="Base64 / URL encode">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Encode or decode Base64 and URL-escaped text locally in the browser, useful for tokens, query strings, and quick
        troubleshooting.
      </p>
      <div className="mt-5 grid gap-4 sm:grid-cols-[220px_1fr]">
        <Field>
          <Label>Mode</Label>
          <select
            className={inputClass()}
            value={mode}
            onChange={(event) => {
              const nextMode = event.target.value as EncoderMode;
              setMode(nextMode);
              setInput(encoderSamples[nextMode]);
            }}
          >
            <option value="base64-encode">Base64 encode</option>
            <option value="base64-decode">Base64 decode</option>
            <option value="url-encode">URL encode</option>
            <option value="url-decode">URL decode</option>
          </select>
        </Field>
        <Field>
          <Label>Input</Label>
          <textarea
            className={`${inputClass(Boolean(error), input === sample)} min-h-32 font-mono`}
            value={input}
            onChange={(event) => setInput(event.target.value)}
            onFocus={() => clearExampleValue(input, sample, setInput)}
            onBlur={() => restoreExampleValue(input, sample, setInput)}
          />
          {error && <p className="text-xs leading-5 text-red-300">{error}</p>}
        </Field>
      </div>
      {error ? (
        <div className="mt-4 rounded-2xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-100">
          Fix the input before using the output.
        </div>
      ) : (
        <CommandBlock>{output}</CommandBlock>
      )}
    </Panel>
  );
}

type DateOrder = 'day-first' | 'month-first';
type TimeCycle = '24h' | '12h';

function twoDigit(value: number) {
  return value.toString().padStart(2, '0');
}

function formatLocalDateTime(date: Date, dateOrder: DateOrder, timeCycle: TimeCycle) {
  const day = twoDigit(date.getDate());
  const month = twoDigit(date.getMonth() + 1);
  const year = date.getFullYear();
  const datePart = dateOrder === 'day-first' ? `${day}/${month}/${year}` : `${month}/${day}/${year}`;
  const hours = date.getHours();
  const minutes = twoDigit(date.getMinutes());
  const seconds = twoDigit(date.getSeconds());

  if (timeCycle === '12h') {
    const period = hours >= 12 ? 'PM' : 'AM';
    const displayHours = twoDigit(hours % 12 || 12);
    return `${datePart} ${displayHours}:${minutes}:${seconds} ${period}`;
  }

  return `${datePart} ${twoDigit(hours)}:${minutes}:${seconds}`;
}

function parseLocalDateTime(value: string, dateOrder: DateOrder, timeCycle: TimeCycle) {
  const trimmedValue = value.trim();
  const match =
    timeCycle === '12h'
      ? trimmedValue.match(/^(\d{2})\/(\d{2})\/(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})\s*(AM|PM)$/i)
      : trimmedValue.match(/^(\d{2})\/(\d{2})\/(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})$/);

  if (!match) {
    return null;
  }

  const firstPart = Number(match[1]);
  const secondPart = Number(match[2]);
  const year = Number(match[3]);
  let hours = Number(match[4]);
  const minutes = Number(match[5]);
  const seconds = Number(match[6]);
  const day = dateOrder === 'day-first' ? firstPart : secondPart;
  const month = dateOrder === 'day-first' ? secondPart : firstPart;

  if (timeCycle === '12h') {
    if (hours < 1 || hours > 12) {
      return null;
    }

    const period = match[7].toUpperCase();
    hours = period === 'PM' ? (hours % 12) + 12 : hours % 12;
  }

  const date = new Date(year, month - 1, day, hours, minutes, seconds);
  const isValid =
    date.getFullYear() === year &&
    date.getMonth() === month - 1 &&
    date.getDate() === day &&
    date.getHours() === hours &&
    date.getMinutes() === minutes &&
    date.getSeconds() === seconds;

  return isValid ? date : null;
}

type DataTransferMode = 'time' | 'speed' | 'size';
type DataSizeUnit =
  | 'b'
  | 'Kb'
  | 'Mb'
  | 'Gb'
  | 'Tb'
  | 'Pb'
  | 'B'
  | 'KB'
  | 'MB'
  | 'GB'
  | 'TB'
  | 'PB'
  | 'Kib'
  | 'Mib'
  | 'Gib'
  | 'Tib'
  | 'Pib'
  | 'KiB'
  | 'MiB'
  | 'GiB'
  | 'TiB'
  | 'PiB';
type TransferSpeedUnit = 'bps' | 'Kbps' | 'Mbps' | 'Gbps' | 'B/s' | 'KB/s' | 'MB/s' | 'GB/s';
type TransferTimeUnit = 'seconds' | 'minutes' | 'hours' | 'days';

const dataSizeUnits: Record<DataSizeUnit, number> = {
  b: 1,
  Kb: 1_000,
  Mb: 1_000_000,
  Gb: 1_000_000_000,
  Tb: 1_000_000_000_000,
  Pb: 1_000_000_000_000_000,
  B: 8,
  KB: 8_000,
  MB: 8_000_000,
  GB: 8_000_000_000,
  TB: 8_000_000_000_000,
  PB: 8_000_000_000_000_000,
  Kib: 1_024,
  Mib: 1_048_576,
  Gib: 1_073_741_824,
  Tib: 1_099_511_627_776,
  Pib: 1_125_899_906_842_624,
  KiB: 8_192,
  MiB: 8_388_608,
  GiB: 8_589_934_592,
  TiB: 8_796_093_022_208,
  PiB: 9_007_199_254_740_992,
};

const dataSizeUnitLabels: Record<DataSizeUnit, string> = {
  b: 'b (bits)',
  Kb: 'Kb (Kilobits)',
  Mb: 'Mb (Megabits)',
  Gb: 'Gb (Gigabits)',
  Tb: 'Tb (Terabits)',
  Pb: 'Pb (Petabits)',
  B: 'B (Bytes)',
  KB: 'KB (Kilobytes)',
  MB: 'MB (Megabytes)',
  GB: 'GB (Gigabytes)',
  TB: 'TB (Terabytes)',
  PB: 'PB (Petabytes)',
  Kib: 'Kib (Kibibits)',
  Mib: 'Mib (Mebibits)',
  Gib: 'Gib (Gibibits)',
  Tib: 'Tib (Tebibits)',
  Pib: 'Pib (Pebibits)',
  KiB: 'KiB (Kibibytes)',
  MiB: 'MiB (Mebibytes)',
  GiB: 'GiB (Gibibytes)',
  TiB: 'TiB (Tebibytes)',
  PiB: 'PiB (Pebibytes)',
};

const dataSizeUnitList = Object.keys(dataSizeUnits) as DataSizeUnit[];

const transferSpeedUnits: Record<TransferSpeedUnit, number> = {
  bps: 1,
  Kbps: 1_000,
  Mbps: 1_000_000,
  Gbps: 1_000_000_000,
  'B/s': 8,
  'KB/s': 8_000,
  'MB/s': 8_000_000,
  'GB/s': 8_000_000_000,
};

const transferTimeUnits: Record<TransferTimeUnit, number> = {
  seconds: 1,
  minutes: 60,
  hours: 3_600,
  days: 86_400,
};

const dataTransferExamples = {
  size: '500',
  speed: '15',
  time: '4.44',
};

function formatNumber(value: number, maximumFractionDigits = 2) {
  return new Intl.NumberFormat(undefined, {
    maximumFractionDigits,
  }).format(value);
}

function formatDuration(totalSeconds: number) {
  const roundedSeconds = Math.round(totalSeconds);
  const days = Math.floor(roundedSeconds / 86_400);
  const hours = Math.floor((roundedSeconds % 86_400) / 3_600);
  const minutes = Math.floor((roundedSeconds % 3_600) / 60);
  const seconds = roundedSeconds % 60;
  const parts: string[] = [];

  if (days) parts.push(`${days} d`);
  if (hours) parts.push(`${hours} h`);
  if (minutes) parts.push(`${minutes} min`);
  if (seconds || !parts.length) parts.push(`${seconds} sec`);

  return parts.join(' ');
}

function parsePositiveNumber(value: string) {
  const parsedValue = Number(value);

  return value.trim() && Number.isFinite(parsedValue) && parsedValue > 0 ? parsedValue : null;
}

function DataTransferCalculator() {
  const [mode, setMode] = useState<DataTransferMode>('time');
  const [size, setSize] = useState(dataTransferExamples.size);
  const [isSizeExample, setIsSizeExample] = useState(true);
  const [sizeUnit, setSizeUnit] = useState<DataSizeUnit>('MB');
  const [speed, setSpeed] = useState(dataTransferExamples.speed);
  const [isSpeedExample, setIsSpeedExample] = useState(true);
  const [speedUnit, setSpeedUnit] = useState<TransferSpeedUnit>('Mbps');
  const [time, setTime] = useState(dataTransferExamples.time);
  const [isTimeExample, setIsTimeExample] = useState(true);
  const [timeUnit, setTimeUnit] = useState<TransferTimeUnit>('minutes');

  const parsedSize = parsePositiveNumber(size);
  const parsedSpeed = parsePositiveNumber(speed);
  const parsedTime = parsePositiveNumber(time);
  const sizeBits = parsedSize ? parsedSize * dataSizeUnits[sizeUnit] : null;
  const speedBitsPerSecond = parsedSpeed ? parsedSpeed * transferSpeedUnits[speedUnit] : null;
  const timeSeconds = parsedTime ? parsedTime * transferTimeUnits[timeUnit] : null;
  const sizeError = mode !== 'size' && !parsedSize ? 'Enter a file size greater than zero.' : '';
  const speedError = mode !== 'speed' && !parsedSpeed ? 'Enter a transfer speed greater than zero.' : '';
  const timeError = mode !== 'time' && !parsedTime ? 'Enter a transfer time greater than zero.' : '';

  let resultTitle = 'Transfer time';
  let resultOutput = '';
  let detailOutput = '';

  if (mode === 'time' && sizeBits && speedBitsPerSecond) {
    const resultSeconds = sizeBits / speedBitsPerSecond;
    resultOutput = formatDuration(resultSeconds);
    detailOutput = [
      `${formatNumber(resultSeconds, 2)} seconds`,
      `${formatNumber(resultSeconds / 60, 2)} minutes`,
      `${formatNumber(resultSeconds / 3_600, 2)} hours`,
    ].join('\n');
  }

  if (mode === 'speed' && sizeBits && timeSeconds) {
    const resultBitsPerSecond = sizeBits / timeSeconds;
    resultTitle = 'Required transfer speed';
    resultOutput = `${formatNumber(resultBitsPerSecond / 1_000_000, 2)} Mbps`;
    detailOutput = [
      `${formatNumber(resultBitsPerSecond, 2)} bps`,
      `${formatNumber(resultBitsPerSecond / 1_000_000, 2)} Mbps`,
      `${formatNumber(resultBitsPerSecond / 8_000_000, 2)} MB/s`,
    ].join('\n');
  }

  if (mode === 'size' && speedBitsPerSecond && timeSeconds) {
    const resultBits = speedBitsPerSecond * timeSeconds;
    resultTitle = 'Transferable data size';
    resultOutput = `${formatNumber(resultBits / dataSizeUnits.GB, 2)} GB`;
    detailOutput = [
      `${formatNumber(resultBits / dataSizeUnits.MB, 2)} MB`,
      `${formatNumber(resultBits / dataSizeUnits.GB, 2)} GB`,
      `${formatNumber(resultBits / dataSizeUnits.TB, 2)} TB`,
      `${formatNumber(resultBits / dataSizeUnits.PB, 2)} PB`,
      `${formatNumber(resultBits / dataSizeUnits.PiB, 2)} PiB`,
    ].join('\n');
  }

  const hasError = Boolean(sizeError || speedError || timeError);

  return (
    <Panel title="Data Transfer Calculator">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Estimate transfer time, required speed, or transferable data size using file size, bandwidth, and duration.
      </p>
      <div className="mt-5 grid gap-4 md:grid-cols-3">
        <button
          className={`rounded-2xl border p-4 text-left transition ${
            mode === 'time'
              ? 'border-emerald-400/50 bg-emerald-950/30'
              : 'border-white/10 bg-zinc-950/60 hover:border-emerald-400/40'
          }`}
          type="button"
          onClick={() => setMode('time')}
        >
          <p className="text-sm font-semibold text-zinc-100">Find time</p>
          <p className="mt-2 text-xs leading-5 text-zinc-400">File size / transfer speed</p>
        </button>
        <button
          className={`rounded-2xl border p-4 text-left transition ${
            mode === 'speed'
              ? 'border-emerald-400/50 bg-emerald-950/30'
              : 'border-white/10 bg-zinc-950/60 hover:border-emerald-400/40'
          }`}
          type="button"
          onClick={() => setMode('speed')}
        >
          <p className="text-sm font-semibold text-zinc-100">Find speed</p>
          <p className="mt-2 text-xs leading-5 text-zinc-400">File size / transfer time</p>
        </button>
        <button
          className={`rounded-2xl border p-4 text-left transition ${
            mode === 'size'
              ? 'border-emerald-400/50 bg-emerald-950/30'
              : 'border-white/10 bg-zinc-950/60 hover:border-emerald-400/40'
          }`}
          type="button"
          onClick={() => setMode('size')}
        >
          <p className="text-sm font-semibold text-zinc-100">Find size</p>
          <p className="mt-2 text-xs leading-5 text-zinc-400">Speed x transfer time</p>
        </button>
      </div>
      <div className="mt-6 grid gap-6 xl:grid-cols-[1fr_0.9fr]">
        <div className="grid gap-4">
          {mode !== 'size' && (
            <div className="grid gap-4 sm:grid-cols-[1fr_160px]">
              <Field>
                <Label>File size</Label>
                <input
                  className={inputClass(Boolean(sizeError), isSizeExample)}
                  placeholder={dataTransferExamples.size}
                  value={size}
                  onFocus={() => {
                    if (isSizeExample) {
                      setSize('');
                      setIsSizeExample(false);
                    }
                  }}
                  onChange={(event) => {
                    setSize(event.target.value);
                    setIsSizeExample(false);
                  }}
                  onBlur={() => {
                    if (!size.trim()) {
                      setSize(dataTransferExamples.size);
                      setIsSizeExample(true);
                    }
                  }}
                />
                {sizeError && <p className="text-xs leading-5 text-red-300">{sizeError}</p>}
              </Field>
              <Field>
                <Label>Unit</Label>
                <select
                  className={inputClass()}
                  value={sizeUnit}
                  onChange={(event) => setSizeUnit(event.target.value as DataSizeUnit)}
                >
                  {dataSizeUnitList.map((unit) => (
                    <option key={unit} value={unit}>
                      {dataSizeUnitLabels[unit]}
                    </option>
                  ))}
                </select>
              </Field>
            </div>
          )}
          {mode !== 'speed' && (
            <div className="grid gap-4 sm:grid-cols-[1fr_160px]">
              <Field>
                <Label>Transfer speed</Label>
                <input
                  className={inputClass(Boolean(speedError), isSpeedExample)}
                  placeholder={dataTransferExamples.speed}
                  value={speed}
                  onFocus={() => {
                    if (isSpeedExample) {
                      setSpeed('');
                      setIsSpeedExample(false);
                    }
                  }}
                  onChange={(event) => {
                    setSpeed(event.target.value);
                    setIsSpeedExample(false);
                  }}
                  onBlur={() => {
                    if (!speed.trim()) {
                      setSpeed(dataTransferExamples.speed);
                      setIsSpeedExample(true);
                    }
                  }}
                />
                {speedError && <p className="text-xs leading-5 text-red-300">{speedError}</p>}
              </Field>
              <Field>
                <Label>Unit</Label>
                <select
                  className={inputClass()}
                  value={speedUnit}
                  onChange={(event) => setSpeedUnit(event.target.value as TransferSpeedUnit)}
                >
                  {Object.keys(transferSpeedUnits).map((unit) => (
                    <option key={unit} value={unit}>
                      {unit}
                    </option>
                  ))}
                </select>
              </Field>
            </div>
          )}
          {mode !== 'time' && (
            <div className="grid gap-4 sm:grid-cols-[1fr_160px]">
              <Field>
                <Label>Transfer time</Label>
                <input
                  className={inputClass(Boolean(timeError), isTimeExample)}
                  placeholder={dataTransferExamples.time}
                  value={time}
                  onFocus={() => {
                    if (isTimeExample) {
                      setTime('');
                      setIsTimeExample(false);
                    }
                  }}
                  onChange={(event) => {
                    setTime(event.target.value);
                    setIsTimeExample(false);
                  }}
                  onBlur={() => {
                    if (!time.trim()) {
                      setTime(dataTransferExamples.time);
                      setIsTimeExample(true);
                    }
                  }}
                />
                {timeError && <p className="text-xs leading-5 text-red-300">{timeError}</p>}
              </Field>
              <Field>
                <Label>Unit</Label>
                <select
                  className={inputClass()}
                  value={timeUnit}
                  onChange={(event) => setTimeUnit(event.target.value as TransferTimeUnit)}
                >
                  {Object.keys(transferTimeUnits).map((unit) => (
                    <option key={unit} value={unit}>
                      {unit}
                    </option>
                  ))}
                </select>
              </Field>
            </div>
          )}
        </div>
        <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <p className="text-sm font-semibold text-zinc-200">{resultTitle}</p>
          {hasError ? (
            <p className="mt-3 text-sm leading-6 text-red-300">Enter the required values to calculate the result.</p>
          ) : (
            <>
              <p className="mt-3 font-mono text-xl font-semibold text-emerald-300">{resultOutput}</p>
              <CommandBlock>{detailOutput}</CommandBlock>
            </>
          )}
        </div>
      </div>
    </Panel>
  );
}

function InformationUnitsCalculator() {
  const exampleValue = '1024';
  const [inputValue, setInputValue] = useState(exampleValue);
  const [isInputExample, setIsInputExample] = useState(true);
  const [fromUnit, setFromUnit] = useState<DataSizeUnit>('MB');
  const [toUnit, setToUnit] = useState<DataSizeUnit>('MiB');
  const parsedValue = parsePositiveNumber(inputValue);
  const inputError = parsedValue ? '' : 'Enter a value greater than zero.';
  const convertedValue = parsedValue ? (parsedValue * dataSizeUnits[fromUnit]) / dataSizeUnits[toUnit] : null;
  const resultText = convertedValue === null ? '' : `${formatNumber(convertedValue, 8)} ${toUnit}`;
  const rateResultText = convertedValue === null ? '' : `${formatNumber(convertedValue, 8)} ${toUnit}/s`;
  const detailOutput =
    convertedValue === null
      ? ''
      : [
          `${formatNumber(parsedValue ?? 0, 8)} ${fromUnit}`,
          `= ${formatNumber(convertedValue, 8)} ${toUnit}`,
          `= ${formatNumber((parsedValue ?? 0) * dataSizeUnits[fromUnit], 2)} bits`,
        ].join('\n');
  const rateDetailOutput =
    convertedValue === null
      ? ''
      : [
          `${formatNumber(parsedValue ?? 0, 8)} ${fromUnit}/s`,
          `= ${formatNumber(convertedValue, 8)} ${toUnit}/s`,
          `= ${formatNumber((parsedValue ?? 0) * dataSizeUnits[fromUnit], 2)} bps`,
        ].join('\n');

  return (
    <Panel title="Units of information calculator">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Convert between information units and matching per-second data-rate units using the same decimal and binary units
        as the Data Transfer Calculator.
      </p>
      <div className="mt-6 grid gap-6 xl:grid-cols-[1fr_0.9fr]">
        <div className="grid gap-4">
          <Field>
            <Label>Value</Label>
            <input
              className={inputClass(Boolean(inputError), isInputExample)}
              placeholder={exampleValue}
              value={inputValue}
              onFocus={() => {
                if (isInputExample) {
                  setInputValue('');
                  setIsInputExample(false);
                }
              }}
              onChange={(event) => {
                setInputValue(event.target.value);
                setIsInputExample(false);
              }}
              onBlur={() => {
                if (!inputValue.trim()) {
                  setInputValue(exampleValue);
                  setIsInputExample(true);
                }
              }}
            />
            {inputError && <p className="text-xs leading-5 text-red-300">{inputError}</p>}
          </Field>
          <div className="grid gap-4 md:grid-cols-2">
            <Field>
              <Label>From</Label>
              <select className={inputClass()} value={fromUnit} onChange={(event) => setFromUnit(event.target.value as DataSizeUnit)}>
                {dataSizeUnitList.map((unit) => (
                  <option key={unit} value={unit}>
                    {dataSizeUnitLabels[unit]}
                  </option>
                ))}
              </select>
            </Field>
            <Field>
              <Label>To</Label>
              <select className={inputClass()} value={toUnit} onChange={(event) => setToUnit(event.target.value as DataSizeUnit)}>
                {dataSizeUnitList.map((unit) => (
                  <option key={unit} value={unit}>
                    {dataSizeUnitLabels[unit]}
                  </option>
                ))}
              </select>
            </Field>
          </div>
        </div>
        <div className="grid gap-4">
          <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
            <p className="text-sm font-semibold text-zinc-200">Converted value</p>
            {inputError ? (
              <p className="mt-3 text-sm leading-6 text-red-300">Enter a valid value to calculate the result.</p>
            ) : (
              <>
                <p className="mt-3 break-all font-mono text-xl font-semibold text-emerald-300">{resultText}</p>
                <CommandBlock>{detailOutput}</CommandBlock>
              </>
            )}
          </div>
          <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
            <p className="text-sm font-semibold text-zinc-200">Converted value per second</p>
            {inputError ? (
              <p className="mt-3 text-sm leading-6 text-red-300">Enter a valid value to calculate the result.</p>
            ) : (
              <>
                <p className="mt-3 break-all font-mono text-xl font-semibold text-emerald-300">{rateResultText}</p>
                <CommandBlock>{rateDetailOutput}</CommandBlock>
              </>
            )}
          </div>
        </div>
      </div>
    </Panel>
  );
}

type CsrKeyType = 'rsa' | 'ec';
type CsrSignatureHash = 'SHA-256' | 'SHA-384' | 'SHA-512';
type CsrOutputFormat = 'pem-pkcs10' | 'der-pkcs10';
type PrivateKeyOutputFormat = 'pkcs8-pem' | 'encrypted-pkcs8-pem' | 'traditional-rsa-pem' | 'traditional-ec-pem' | 'pkcs8-der';

type CsrSanEntry = {
  id: number;
  value: string;
  isExample: boolean;
};

type CsrGeneratedOutput = {
  csrOutput: string;
  privateKeyOutput: string;
  publicKeyPem: string;
  csrFileName: string;
  privateKeyFileName: string;
  publicKeyFileName: string;
};

const csrSanLimit = 100;
const csrExampleDomain = 'app.example.com';
const csrExampleAdditionalDomain = 'www.example.com';
const csrExampleCountry = 'SK';
const csrKeyProfiles = {
  rsa: {
    label: 'RSA',
    sizes: ['2048', '3072', '4096'],
    typical: 'RSA 2048 is the common baseline. RSA 3072 is a stronger long-life choice. RSA 4096 is accepted but slower.',
  },
  ec: {
    label: 'ECDSA',
    sizes: ['P-256', 'P-384', 'P-521'],
    typical: 'ECDSA P-256 is typically used for modern TLS. P-384 is common for higher assurance. P-521 is less common.',
  },
} as const;

const csrHashOptions: CsrSignatureHash[] = ['SHA-256', 'SHA-384', 'SHA-512'];

const csrKeySizeNotes = {
  rsa: {
    '2048': 'RSA 2048 is the usual public TLS baseline and the most compatible RSA choice.',
    '3072': 'RSA 3072 gives a stronger margin while staying broadly compatible.',
    '4096': 'RSA 4096 is accepted by many systems but generation and handshakes are slower.',
  },
  ec: {
    'P-256': 'P-256 is the normal modern ECDSA choice for public TLS.',
    'P-384': 'P-384 is used when policy asks for a stronger elliptic curve.',
    'P-521': 'P-521 is valid but less commonly deployed and may have compatibility limits.',
  },
} as const;

const csrSignatureHashNotes: Record<CsrSignatureHash, string> = {
  'SHA-256': 'SHA-256 is the standard default for most CSRs.',
  'SHA-384': 'SHA-384 is commonly paired with stronger policy profiles such as P-384.',
  'SHA-512': 'SHA-512 is available for stricter policies, but it is rarely necessary for normal TLS CSRs.',
};

const csrOutputFormatLabels: Record<CsrOutputFormat, string> = {
  'pem-pkcs10': 'PEM / PKCS#10',
  'der-pkcs10': 'DER / PKCS#10',
};

const privateKeyOutputFormatLabels: Record<PrivateKeyOutputFormat, string> = {
  'pkcs8-pem': 'PKCS#8 PEM',
  'encrypted-pkcs8-pem': 'Encrypted PKCS#8 PEM',
  'traditional-rsa-pem': 'Traditional RSA PEM',
  'traditional-ec-pem': 'Traditional EC PEM',
  'pkcs8-der': 'PKCS#8 DER',
};

function CsrGenerator() {
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

  const commonNameError = validateCsrCommonName(commonName);
  const countryError = validateCsrCountry(country);
  const emailError = email.trim() ? validateCsrEmail(email) : '';
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
          <Field>
            <Label>CN / Common Name *</Label>
            <input
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
            {commonNameError && <p className="text-xs leading-5 text-red-300">{commonNameError}</p>}
          </Field>
          <Field>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <Label>SANs / DNS names / IPs *</Label>
              <button
                className="rounded-lg border border-emerald-500/30 px-3 py-1 text-sm font-semibold text-emerald-300 transition hover:border-emerald-400 hover:bg-emerald-500/10 disabled:cursor-not-allowed disabled:opacity-50"
                type="button"
                onClick={addSan}
                disabled={sans.length >= csrSanLimit}
              >
                +
              </button>
            </div>
            <div className="grid gap-2">
              {sans.map((san, index) => (
                <div key={san.id} className="grid gap-2 sm:grid-cols-[1fr_auto]">
                  <input
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
                    disabled={index === 0}
                  >
                    Remove
                  </button>
                  {sanErrors[index] && <p className="text-xs leading-5 text-red-300 sm:col-span-2">{sanErrors[index]}</p>}
                  {!sanErrors[index] && sanWarnings[index] && (
                    <p className="text-xs leading-5 text-amber-300 sm:col-span-2">{sanWarnings[index]}</p>
                  )}
                </div>
              ))}
            </div>
            {!hasRequiredSan && <p className="text-xs leading-5 text-red-300">At least one SAN is required.</p>}
            <p className="text-xs leading-5 text-zinc-500">
              Public TLS certificates must include at least one DNS name or IP address in SAN. The CA/B Forum Baseline
              Requirements do not define a universal SAN count maximum, so this form caps entries at {csrSanLimit}; your
              CA product may allow fewer.
            </p>
            <p className="text-xs leading-5 text-zinc-500">
              IP addresses are encoded as IP Address SAN entries, not DNS entries. Public CAs may include IP SANs only for
              public IPs that you can validate/control. Private/internal IPs such as 10.x.x.x, 172.16-31.x.x,
              192.168.x.x, localhost, and link-local addresses are not suitable for public CA certificates. For internal
              IPs, use an internal/private CA.
            </p>
          </Field>
          <div className="grid gap-4 md:grid-cols-2">
            <Field>
              <Label>Organization</Label>
              <input
                className={inputClass()}
                value={organization}
                onChange={(event) => setOrganization(event.target.value)}
              />
            </Field>
            <Field>
              <Label>Organizational Unit</Label>
              <input
                className={inputClass()}
                value={organizationalUnit}
                onChange={(event) => setOrganizationalUnit(event.target.value)}
              />
            </Field>
            <Field>
              <Label>Email</Label>
              <input
                className={inputClass(Boolean(emailError))}
                value={email}
                onChange={(event) => setEmail(event.target.value)}
              />
              {emailError && <p className="text-xs leading-5 text-red-300">{emailError}</p>}
            </Field>
            <Field>
              <Label>Country *</Label>
              <input
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
              {countryError && <p className="text-xs leading-5 text-red-300">{countryError}</p>}
            </Field>
            <Field>
              <Label>State / Province</Label>
              <input className={inputClass()} value={state} onChange={(event) => setState(event.target.value)} />
            </Field>
            <Field>
              <Label>Locality / City</Label>
              <input
                className={inputClass()}
                value={locality}
                onChange={(event) => setLocality(event.target.value)}
              />
            </Field>
          </div>
          <div className="grid gap-4 md:grid-cols-3">
            <Field>
              <Label>Key type *</Label>
              <select
                className={inputClass()}
                value={keyType}
                onChange={(event) => changeKeyType(event.target.value as CsrKeyType)}
              >
                <option value="rsa">RSA</option>
                <option value="ec">ECDSA</option>
              </select>
            </Field>
            <Field>
              <Label>Key size *</Label>
              <select className={inputClass()} value={keySize} onChange={(event) => setKeySize(event.target.value)}>
                {csrKeyProfiles[keyType].sizes.map((size) => (
                  <option key={size} value={size}>
                    {size}
                  </option>
                ))}
              </select>
            </Field>
            <Field>
              <Label>Signature hash</Label>
              <select
                className={inputClass()}
                value={signatureHash}
                onChange={(event) => setSignatureHash(event.target.value as CsrSignatureHash)}
              >
                {csrHashOptions.map((hash) => (
                  <option key={hash} value={hash}>
                    {hash}
                  </option>
                ))}
              </select>
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
                        checked={csrOutputFormat === 'pem-pkcs10'}
                        onChange={() => setCsrOutputFormat('pem-pkcs10')}
                      />
                      <span>PEM / PKCS#10 <span className="text-zinc-500">recommended</span></span>
                    </label>
                    <label className="flex items-start gap-3">
                      <input
                        className="mt-1 accent-emerald-400"
                        type="radio"
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
                        checked={privateKeyOutputFormat === 'pkcs8-pem'}
                        onChange={() => setPrivateKeyOutputFormat('pkcs8-pem')}
                      />
                      <span>PKCS#8 PEM <span className="text-zinc-500">recommended</span></span>
                    </label>
                    <label className="flex items-start gap-3">
                      <input
                        className="mt-1 accent-emerald-400"
                        type="radio"
                        checked={privateKeyOutputFormat === 'encrypted-pkcs8-pem'}
                        onChange={() => setPrivateKeyOutputFormat('encrypted-pkcs8-pem')}
                      />
                      <span>Encrypted PKCS#8 PEM <span className="text-zinc-500">password protected</span></span>
                    </label>
                    <label className="flex items-start gap-3">
                      <input
                        className="mt-1 accent-emerald-400 disabled:cursor-not-allowed"
                        type="radio"
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
                        checked={privateKeyOutputFormat === 'pkcs8-der'}
                        onChange={() => setPrivateKeyOutputFormat('pkcs8-der')}
                      />
                      <span>PKCS#8 DER <span className="text-zinc-500">binary, advanced</span></span>
                    </label>
                  </div>
                </fieldset>
                {privateKeyOutputFormat === 'encrypted-pkcs8-pem' && (
                  <Field>
                    <Label>Encryption password *</Label>
                    <input
                      className={inputClass(Boolean(privateKeyPasswordError))}
                      type="password"
                      value={privateKeyPassword}
                      onChange={(event) => setPrivateKeyPassword(event.target.value)}
                    />
                    {privateKeyPasswordError && <p className="text-xs leading-5 text-red-300">{privateKeyPasswordError}</p>}
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

function getCsrKeySizeNotes(keyType: CsrKeyType): Record<string, string> {
  return csrKeySizeNotes[keyType];
}

type CreateCsrInput = {
  commonName: string;
  organization: string;
  organizationalUnit: string;
  email: string;
  country: string;
  locality: string;
  state: string;
  keyType: CsrKeyType;
  keySize: string;
  signatureHash: CsrSignatureHash;
  csrOutputFormat: CsrOutputFormat;
  privateKeyOutputFormat: PrivateKeyOutputFormat;
  privateKeyPassword: string;
  sans: string[];
};

async function createCsr(input: CreateCsrInput): Promise<CsrGeneratedOutput> {
  const keyAlgorithm =
    input.keyType === 'rsa'
      ? {
          name: 'RSASSA-PKCS1-v1_5',
          modulusLength: Number(input.keySize),
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: input.signatureHash,
        }
      : {
          name: 'ECDSA',
          namedCurve: input.keySize,
        };
  const signingAlgorithm =
    input.keyType === 'rsa' ? { name: 'RSASSA-PKCS1-v1_5' } : { name: 'ECDSA', hash: input.signatureHash };
  const keyPair = await crypto.subtle.generateKey(keyAlgorithm, true, ['sign', 'verify']);
  const privateKeyDer = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
  const publicKeyDer = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
  const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const certificationRequestInfo = derSequence(
    derInteger(new Uint8Array([0])),
    derName([
      ['2.5.4.6', input.country],
      ['2.5.4.8', input.state],
      ['2.5.4.7', input.locality],
      ['2.5.4.10', input.organization],
      ['2.5.4.11', input.organizationalUnit],
      ['2.5.4.3', input.commonName],
      ['1.2.840.113549.1.9.1', input.email],
    ]),
    publicKeyDer,
    derContext(0, derAttributeExtensionRequest(input.sans))
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign(signingAlgorithm, keyPair.privateKey, certificationRequestInfo)
  );
  const encodedSignature = input.keyType === 'ec' ? derEncodeEcdsaSignature(signature) : signature;
  const csrDer = derSequence(
    certificationRequestInfo,
    derSignatureAlgorithm(input.keyType, input.signatureHash),
    derBitString(encodedSignature)
  );
  const safeCommonName = createSafeFileName(input.commonName);
  const csrOutput = input.csrOutputFormat === 'pem-pkcs10' ? pemEncode('CERTIFICATE REQUEST', csrDer) : base64Encode(csrDer);
  const privateKeyOutput = await formatPrivateKeyOutput(input, privateKeyDer, privateJwk);

  return {
    csrOutput,
    privateKeyOutput,
    publicKeyPem: pemEncode('PUBLIC KEY', publicKeyDer),
    csrFileName: `${safeCommonName}.csr`,
    privateKeyFileName: `${safeCommonName}_private-key.pem`,
    publicKeyFileName: `${safeCommonName}_public-key.pem`,
  };
}

async function formatPrivateKeyOutput(input: CreateCsrInput, privateKeyDer: Uint8Array, privateJwk: JsonWebKey) {
  switch (input.privateKeyOutputFormat) {
    case 'encrypted-pkcs8-pem':
      return pemEncode('ENCRYPTED PRIVATE KEY', await encryptPkcs8PrivateKey(privateKeyDer, input.privateKeyPassword));
    case 'traditional-rsa-pem':
      return pemEncode('RSA PRIVATE KEY', derRsaPrivateKey(privateJwk));
    case 'traditional-ec-pem':
      return pemEncode('EC PRIVATE KEY', derEcPrivateKey(privateJwk));
    case 'pkcs8-der':
      return base64Encode(privateKeyDer);
    case 'pkcs8-pem':
    default:
      return pemEncode('PRIVATE KEY', privateKeyDer);
  }
}

function createSafeFileName(value: string) {
  return (
    value.trim().replace(/^\*\./, 'wildcard.').replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '') ||
    'request'
  );
}

function validateCsrCommonName(value: string) {
  const trimmedValue = value.trim();

  if (!trimmedValue) {
    return 'Common Name is required.';
  }

  if (trimmedValue.length > 253) {
    return 'Common Name must be 253 characters or fewer.';
  }

  if (!isValidDnsName(trimmedValue) && !isValidIpAddress(trimmedValue)) {
    return 'Use a DNS name, wildcard DNS name, IPv4 address, or IPv6 address.';
  }

  return '';
}

function validateCsrCountry(value: string) {
  return /^[A-Z]{2}$/.test(value.trim().toUpperCase())
    ? ''
    : 'Country must be a two-letter ISO code, for example DE or US.';
}

function validateCsrEmail(value: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim()) ? '' : 'Enter a valid email address.';
}

function validateCsrSan(value: string) {
  const trimmedValue = value.trim();

  if (!trimmedValue) {
    return 'SAN value is required.';
  }

  if (!isValidDnsName(trimmedValue) && !isValidIpAddress(trimmedValue)) {
    return 'Use a DNS name, wildcard DNS name, IPv4 address, or IPv6 address.';
  }

  return '';
}

function getCsrSanWarning(value: string) {
  const trimmedValue = value.trim().toLowerCase();

  if (!trimmedValue) {
    return '';
  }

  if (trimmedValue === 'localhost') {
    return 'localhost is not suitable for public CA certificates. Use an internal/private CA.';
  }

  if (isValidIpAddress(trimmedValue) && !isPublicIpAddress(trimmedValue)) {
    return 'Private, loopback, and link-local IPs are not suitable for public CA certificates. Use an internal/private CA.';
  }

  return '';
}

function isValidDnsName(value: string) {
  const normalizedValue = value.toLowerCase();
  const withoutWildcard = normalizedValue.startsWith('*.') ? normalizedValue.slice(2) : normalizedValue;

  if (!withoutWildcard || withoutWildcard.length > 253 || withoutWildcard.endsWith('.')) {
    return false;
  }

  return withoutWildcard.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}

function isValidIpAddress(value: string) {
  return isValidIpv4Address(value) || isValidIpv6Address(value);
}

function isPublicIpAddress(value: string) {
  return isValidIpv4Address(value) ? isPublicIpv4Address(value) : isPublicIpv6Address(value);
}

function isPublicIpv4Address(value: string) {
  const [firstOctet, secondOctet] = value.split('.').map((octet) => Number(octet));

  if (firstOctet === 10 || firstOctet === 127 || firstOctet === 0) {
    return false;
  }

  if (firstOctet === 172 && secondOctet >= 16 && secondOctet <= 31) {
    return false;
  }

  if (firstOctet === 192 && secondOctet === 168) {
    return false;
  }

  if (firstOctet === 169 && secondOctet === 254) {
    return false;
  }

  return true;
}

function isPublicIpv6Address(value: string) {
  const bytes = parseIpAddress(value);
  const firstByte = bytes[0];
  const secondByte = bytes[1];

  if (
    bytes.every((byte) => byte === 0) ||
    bytes.every((byte, index) => (index === 15 ? byte === 1 : byte === 0))
  ) {
    return false;
  }

  if ((firstByte & 0xfe) === 0xfc) {
    return false;
  }

  if (firstByte === 0xfe && (secondByte & 0xc0) === 0x80) {
    return false;
  }

  return true;
}

function isValidIpv4Address(value: string) {
  const octets = value.split('.');

  return (
    octets.length === 4 &&
    octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) >= 0 && Number(octet) <= 255)
  );
}

function isValidIpv6Address(value: string) {
  if (!value.includes(':')) {
    return false;
  }

  const normalizedValue = value.toLowerCase();

  if (!/^[0-9a-f:.]+$/.test(normalizedValue)) {
    return false;
  }

  const parts = normalizedValue.split('::');

  if (parts.length > 2) {
    return false;
  }

  const left = parts[0] ? parts[0].split(':') : [];
  const right = parts[1] ? parts[1].split(':') : [];
  const groups = [...left, ...right];
  const hasValidGroups = groups.every((group) => /^[0-9a-f]{1,4}$/.test(group));

  return hasValidGroups && (parts.length === 2 ? groups.length < 8 : groups.length === 8);
}

function parseIpAddress(value: string) {
  if (isValidIpv4Address(value)) {
    return new Uint8Array(value.split('.').map((octet) => Number(octet)));
  }

  const parts = value.toLowerCase().split('::');
  const left = parts[0] ? parts[0].split(':') : [];
  const right = parts[1] ? parts[1].split(':') : [];
  const missingGroupCount = 8 - left.length - right.length;
  const groups = [...left, ...Array(Math.max(missingGroupCount, 0)).fill('0'), ...right].map((group) =>
    parseInt(group, 16)
  );
  const bytes = new Uint8Array(16);

  groups.forEach((group, index) => {
    bytes[index * 2] = group >> 8;
    bytes[index * 2 + 1] = group & 255;
  });

  return bytes;
}

function derAttributeExtensionRequest(sans: string[]) {
  const generalNames = derSequence(
    ...sans.map((san) =>
      isValidIpAddress(san) ? derRaw(0x87, parseIpAddress(san)) : derRaw(0x82, asciiBytes(san.toLowerCase()))
    )
  );
  const sanExtension = derSequence(derObjectIdentifier('2.5.29.17'), derOctetString(generalNames));
  const extensions = derSequence(sanExtension);

  return derSequence(derObjectIdentifier('1.2.840.113549.1.9.14'), derSet(extensions));
}

async function encryptPkcs8PrivateKey(privateKeyDer: Uint8Array, password: string) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 250000;
  const passwordKey = await crypto.subtle.importKey('raw', utf8Bytes(password), 'PBKDF2', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    passwordKey,
    { name: 'AES-CBC', length: 256 },
    false,
    ['encrypt']
  );
  const encryptedBytes = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, toArrayBuffer(privateKeyDer))
  );
  const pbes2Algorithm = derSequence(
    derObjectIdentifier('1.2.840.113549.1.5.13'),
    derSequence(
      derSequence(
        derObjectIdentifier('1.2.840.113549.1.5.12'),
        derSequence(
          derOctetString(salt),
          derInteger(numberToBytes(iterations)),
          derSequence(derObjectIdentifier('1.2.840.113549.2.9'), derRaw(0x05, new Uint8Array()))
        )
      ),
      derSequence(derObjectIdentifier('2.16.840.1.101.3.4.1.42'), derOctetString(iv))
    )
  );

  return derSequence(pbes2Algorithm, derOctetString(encryptedBytes));
}

function derRsaPrivateKey(privateJwk: JsonWebKey) {
  const fields = ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'] as const;

  return derSequence(
    derInteger(new Uint8Array([0])),
    ...fields.map((field) => derInteger(base64UrlDecode(privateJwk[field] ?? '')))
  );
}

function derEcPrivateKey(privateJwk: JsonWebKey) {
  const curveOidByName: Record<string, string> = {
    'P-256': '1.2.840.10045.3.1.7',
    'P-384': '1.3.132.0.34',
    'P-521': '1.3.132.0.35',
  };
  const privateKeyBytes = base64UrlDecode(privateJwk.d ?? '');
  const publicPointBytes = concatBytes(new Uint8Array([4]), base64UrlDecode(privateJwk.x ?? ''), base64UrlDecode(privateJwk.y ?? ''));

  return derSequence(
    derInteger(new Uint8Array([1])),
    derOctetString(privateKeyBytes),
    derContext(0, derObjectIdentifier(curveOidByName[privateJwk.crv ?? ''] ?? curveOidByName['P-256'])),
    derContext(1, derBitString(publicPointBytes))
  );
}

function derName(attributes: string[][]) {
  return derSequence(
    ...attributes
      .filter(([, value]) => value)
      .map(([oid, value]) => derSet(derSequence(derObjectIdentifier(oid), derDirectoryString(oid, value))))
  );
}

function derDirectoryString(oid: string, value: string) {
  if (oid === '2.5.4.6' || oid === '1.2.840.113549.1.9.1') {
    return derRaw(oid === '2.5.4.6' ? 0x13 : 0x16, asciiBytes(value));
  }

  return derRaw(0x0c, utf8Bytes(value));
}

function derSignatureAlgorithm(keyType: CsrKeyType, hash: CsrSignatureHash) {
  if (keyType === 'rsa') {
    const oidByHash: Record<CsrSignatureHash, string> = {
      'SHA-256': '1.2.840.113549.1.1.11',
      'SHA-384': '1.2.840.113549.1.1.12',
      'SHA-512': '1.2.840.113549.1.1.13',
    };

    return derSequence(derObjectIdentifier(oidByHash[hash]), derRaw(0x05, new Uint8Array()));
  }

  const oidByHash: Record<CsrSignatureHash, string> = {
    'SHA-256': '1.2.840.10045.4.3.2',
    'SHA-384': '1.2.840.10045.4.3.3',
    'SHA-512': '1.2.840.10045.4.3.4',
  };

  return derSequence(derObjectIdentifier(oidByHash[hash]));
}

function derEncodeEcdsaSignature(signature: Uint8Array) {
  const halfLength = signature.length / 2;

  return derSequence(derInteger(signature.slice(0, halfLength)), derInteger(signature.slice(halfLength)));
}

function derSequence(...parts: Uint8Array[]) {
  return derRaw(0x30, concatBytes(...parts));
}

function derSet(...parts: Uint8Array[]) {
  return derRaw(0x31, concatBytes(...parts));
}

function derContext(index: number, content: Uint8Array) {
  return derRaw(0xa0 + index, content);
}

function derInteger(value: Uint8Array) {
  let normalizedValue = trimLeadingZeroBytes(value);

  if (normalizedValue.length === 0) {
    normalizedValue = new Uint8Array([0]);
  }

  if (normalizedValue[0] & 0x80) {
    normalizedValue = concatBytes(new Uint8Array([0]), normalizedValue);
  }

  return derRaw(0x02, normalizedValue);
}

function derBitString(value: Uint8Array) {
  return derRaw(0x03, concatBytes(new Uint8Array([0]), value));
}

function derOctetString(value: Uint8Array) {
  return derRaw(0x04, value);
}

function derObjectIdentifier(oid: string) {
  const parts = oid.split('.').map((part) => Number(part));
  const bytes = [parts[0] * 40 + parts[1]];

  for (const part of parts.slice(2)) {
    const stack = [part & 0x7f];
    let value = part >> 7;

    while (value > 0) {
      stack.unshift((value & 0x7f) | 0x80);
      value >>= 7;
    }

    bytes.push(...stack);
  }

  return derRaw(0x06, new Uint8Array(bytes));
}

function numberToBytes(value: number) {
  const bytes = [];
  let remainingValue = value;

  while (remainingValue > 0) {
    bytes.unshift(remainingValue & 255);
    remainingValue >>= 8;
  }

  return new Uint8Array(bytes.length ? bytes : [0]);
}

function derRaw(tag: number, content: Uint8Array) {
  return concatBytes(new Uint8Array([tag]), derLength(content.length), content);
}

function derLength(length: number) {
  if (length < 128) {
    return new Uint8Array([length]);
  }

  const bytes = [];
  let remainingLength = length;

  while (remainingLength > 0) {
    bytes.unshift(remainingLength & 255);
    remainingLength >>= 8;
  }

  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function trimLeadingZeroBytes(value: Uint8Array) {
  let index = 0;

  while (index < value.length - 1 && value[index] === 0) {
    index += 1;
  }

  return value.slice(index);
}

function concatBytes(...parts: Uint8Array[]) {
  const totalLength = parts.reduce((length, part) => length + part.length, 0);
  const output = new Uint8Array(totalLength);
  let offset = 0;

  parts.forEach((part) => {
    output.set(part, offset);
    offset += part.length;
  });

  return output;
}

function toArrayBuffer(bytes: Uint8Array) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function asciiBytes(value: string) {
  return new Uint8Array([...value].map((character) => character.charCodeAt(0)));
}

function utf8Bytes(value: string) {
  return new TextEncoder().encode(value);
}

function base64UrlDecode(value: string) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const binary = window.atob(base64);

  return new Uint8Array([...binary].map((character) => character.charCodeAt(0)));
}

function base64Encode(der: Uint8Array) {
  const binary = Array.from(der, (byte) => String.fromCharCode(byte)).join('');

  return window.btoa(binary).match(/.{1,64}/g)?.join('\n') ?? '';
}

function pemEncode(label: string, der: Uint8Array) {
  const lines = base64Encode(der).split('\n');

  return [`-----BEGIN ${label}-----`, ...lines, `-----END ${label}-----`].join('\n');
}

function EpochTool() {
  const [now, setNow] = useState(() => new Date());
  const [timestamp, setTimestamp] = useState(() => Math.floor(Date.now() / 1000).toString());
  const [timestampUnit, setTimestampUnit] = useState<'seconds' | 'milliseconds'>('seconds');
  const [dateOrder, setDateOrder] = useState<DateOrder>('day-first');
  const [timeCycle, setTimeCycle] = useState<TimeCycle>('24h');
  const [dateInput, setDateInput] = useState(() => formatLocalDateTime(new Date(), 'day-first', '24h'));

  useEffect(() => {
    const intervalId = window.setInterval(() => setNow(new Date()), 1000);

    return () => window.clearInterval(intervalId);
  }, []);

  const parsedTimestamp = Number(timestamp);
  const timestampError =
    timestamp.trim() && Number.isFinite(parsedTimestamp) ? '' : 'Unix timestamp must be a number.';
  const timestampDate = timestampError
    ? null
    : new Date(timestampUnit === 'seconds' ? parsedTimestamp * 1000 : parsedTimestamp);
  const dateInputDate = parseLocalDateTime(dateInput, dateOrder, timeCycle);
  const dateInputError = dateInputDate ? '' : `Use ${dateOrder === 'day-first' ? 'DD/MM/YYYY' : 'MM/DD/YYYY'} ${
    timeCycle === '24h' ? 'HH:mm:ss' : 'hh:mm:ss AM/PM'
  }.`;
  const convertedSeconds = dateInputDate && !dateInputError ? Math.floor(dateInputDate.getTime() / 1000).toString() : '';
  const convertedMilliseconds = dateInputDate && !dateInputError ? dateInputDate.getTime().toString() : '';
  const formatLabel = `${dateOrder === 'day-first' ? 'DD/MM/YYYY' : 'MM/DD/YYYY'} ${
    timeCycle === '24h' ? '24-hour' : '12-hour'
  } time with seconds`;
  const dateInputPlaceholder =
    dateOrder === 'day-first'
      ? timeCycle === '24h'
        ? '10/05/2026 14:30:00'
        : '10/05/2026 02:30:00 PM'
      : timeCycle === '24h'
        ? '05/10/2026 14:30:00'
        : '05/10/2026 02:30:00 PM';
  const toggleDateOrder = () => {
    const nextDateOrder = dateOrder === 'day-first' ? 'month-first' : 'day-first';
    const parsedDate = parseLocalDateTime(dateInput, dateOrder, timeCycle);

    setDateOrder(nextDateOrder);

    if (parsedDate) {
      setDateInput(formatLocalDateTime(parsedDate, nextDateOrder, timeCycle));
    }
  };
  const toggleTimeCycle = () => {
    const nextTimeCycle = timeCycle === '24h' ? '12h' : '24h';
    const parsedDate = parseLocalDateTime(dateInput, dateOrder, timeCycle);

    setTimeCycle(nextTimeCycle);

    if (parsedDate) {
      setDateInput(formatLocalDateTime(parsedDate, dateOrder, nextTimeCycle));
    }
  };

  return (
    <Panel title="Epoch & Unix timestamp conversion">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Convert Unix timestamps to readable local time, convert local date-time back to epoch values, and check the current
        time while troubleshooting logs or scheduled jobs.
      </p>
      <div className="mt-4 flex flex-wrap gap-3">
        <button
          className="rounded-full border border-white/10 bg-zinc-950/60 px-4 py-2 text-sm font-semibold text-zinc-200 transition hover:border-emerald-400/40 hover:text-emerald-200"
          type="button"
          onClick={toggleDateOrder}
        >
          {dateOrder === 'day-first' ? 'Use MM/DD/YYYY' : 'Use DD/MM/YYYY'}
        </button>
        <button
          className="rounded-full border border-white/10 bg-zinc-950/60 px-4 py-2 text-sm font-semibold text-zinc-200 transition hover:border-emerald-400/40 hover:text-emerald-200"
          type="button"
          onClick={toggleTimeCycle}
        >
          {timeCycle === '24h' ? 'Use 12-hour time' : 'Use 24-hour time'}
        </button>
      </div>
      <p className="mt-5 text-xs font-semibold uppercase tracking-[0.2em] text-emerald-300">Format in use: {formatLabel}</p>
      <div className="mt-5 grid gap-4 md:grid-cols-3">
        <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <p className="text-sm font-semibold text-zinc-200">Current local time</p>
          <p className="mt-3 font-mono text-sm text-zinc-100">{formatLocalDateTime(now, dateOrder, timeCycle)}</p>
        </div>
        <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <p className="text-sm font-semibold text-zinc-200">Unix seconds</p>
          <p className="mt-3 font-mono text-sm text-emerald-300">{Math.floor(now.getTime() / 1000)}</p>
        </div>
        <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <p className="text-sm font-semibold text-zinc-200">Unix milliseconds</p>
          <p className="mt-3 font-mono text-sm text-emerald-300">{now.getTime()}</p>
        </div>
      </div>
      <div className="mt-6 grid gap-6 xl:grid-cols-2">
        <div>
          <h3 className="text-lg font-semibold">Timestamp to local time</h3>
          <div className="mt-4 grid gap-4 sm:grid-cols-[1fr_180px]">
            <Field>
              <Label>Unix timestamp</Label>
              <input
                className={inputClass(Boolean(timestampError))}
                value={timestamp}
                onChange={(event) => setTimestamp(event.target.value)}
              />
              {timestampError && <p className="text-xs leading-5 text-red-300">{timestampError}</p>}
            </Field>
            <Field>
              <Label>Unit</Label>
              <select
                className={inputClass()}
                value={timestampUnit}
                onChange={(event) => setTimestampUnit(event.target.value as 'seconds' | 'milliseconds')}
              >
                <option value="seconds">Seconds</option>
                <option value="milliseconds">Milliseconds</option>
              </select>
            </Field>
          </div>
          {!timestampError && timestampDate && (
            <CommandBlock>{`${formatLocalDateTime(timestampDate, dateOrder, timeCycle)}\n${timestampDate.toISOString()}`}</CommandBlock>
          )}
        </div>
        <div>
          <h3 className="text-lg font-semibold">Local time to timestamp</h3>
          <div className="mt-4">
            <Field>
              <Label>Local date and time</Label>
              <input
                className={inputClass(Boolean(dateInputError))}
                placeholder={dateInputPlaceholder}
                value={dateInput}
                onChange={(event) => setDateInput(event.target.value)}
              />
              {dateInputError && <p className="text-xs leading-5 text-red-300">{dateInputError}</p>}
            </Field>
          </div>
          {!dateInputError && (
            <>
              <CommandBlock>{convertedSeconds}</CommandBlock>
              <CommandBlock>{convertedMilliseconds}</CommandBlock>
            </>
          )}
        </div>
      </div>
    </Panel>
  );
}

export default App;
