import { useState } from 'react';

import { CommandBlock } from '../../components/CommandBlock';
import { Field, Label, Panel, inputClass, FieldInput, FieldSelect, FieldError } from '../../components/Panel';
import { clearExampleValue, restoreExampleValue } from '../../components/inputExamples';
import { CommonPortsHint } from '../firewall-shared/CommonPortsHint';
import { firewallExamples, validateIpv4Cidr, validatePort } from '../firewall-shared/firewallHelpers';
import { HelpTooltip } from '../../components/Panel';
import { commonFirewalldServices, firewalldZones, validateZoneName } from './firewalldHelpers';

export function FirewalldZonesBlock() {
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
                <FieldSelect className={inputClass()} value={zonePreset} onChange={(event) => setZonePreset(event.target.value)}>
                  {firewalldZones.map((zoneName) => (
                    <option key={zoneName} value={zoneName}>
                      {zoneName}
                    </option>
                  ))}
                </FieldSelect>
              </Field>
            )}
            {useCustomZone && (
              <Field error={zoneError}>
                <Label>Custom zone name</Label>
                <FieldInput
                  className={inputClass(Boolean(zoneError), customZone === 'app-zone')}
                  value={customZone}
                  onChange={(event) => setCustomZone(event.target.value)}
                  onFocus={() => clearExampleValue(customZone, 'app-zone', setCustomZone)}
                  onBlur={() => restoreExampleValue(customZone, 'app-zone', setCustomZone)}
                />
                <FieldError />
              </Field>
            )}
            <Field>
              <Label>Zone mode</Label>
              <FieldSelect
                className={inputClass()}
                value={mode}
                onChange={(event) => setMode(event.target.value as 'runtime' | 'permanent')}
              >
                <option value="permanent">Permanent</option>
                <option value="runtime">Runtime</option>
              </FieldSelect>
            </Field>
            {useSource && (
              <Field error={sourceError}>
                <Label>Source IPv4</Label>
                <FieldInput
                  className={inputClass(Boolean(sourceError), source === firewallExamples.source)}
                  value={source}
                  onChange={(event) => setSource(event.target.value)}
                  onFocus={() => clearExampleValue(source, firewallExamples.source, setSource)}
                  onBlur={() => restoreExampleValue(source, firewallExamples.source, setSource)}
                />
                <FieldError />
              </Field>
            )}
            {useService && (
              <Field>
                <Label>Service</Label>
                <FieldSelect className={inputClass()} value={service} onChange={(event) => setService(event.target.value)}>
                  {commonFirewalldServices.map((serviceName) => (
                    <option key={serviceName} value={serviceName}>
                      {serviceName}
                    </option>
                  ))}
                </FieldSelect>
              </Field>
            )}
            {usePort && (
              <>
                <Field error={portError}>
                  <Label>Destination port</Label>
                  <FieldInput
                    className={inputClass(Boolean(portError), port === firewallExamples.destinationPort)}
                    value={port}
                    onChange={(event) => setPort(event.target.value)}
                    onFocus={() => clearExampleValue(port, firewallExamples.destinationPort, setPort)}
                    onBlur={() => restoreExampleValue(port, firewallExamples.destinationPort, setPort)}
                  />
                  <FieldError />
                </Field>
                <Field>
                  <Label>Protocol</Label>
                  <FieldSelect className={inputClass()} value={protocol} onChange={(event) => setProtocol(event.target.value)}>
                    <option>tcp</option>
                    <option>udp</option>
                  </FieldSelect>
                </Field>
              </>
            )}
            {useIcmp && (
              <Field>
                <Label>ICMP action</Label>
                <FieldSelect
                  className={inputClass()}
                  value={icmpAction}
                  onChange={(event) => setIcmpAction(event.target.value as 'allow' | 'block')}
                >
                  <option value="allow">Allow ping</option>
                  <option value="block">Block ping</option>
                </FieldSelect>
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
            <div className="flex items-center gap-3">
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
              </label>
              <HelpTooltip label="Help with ping controls" text="Controls ping for this zone. Allow ping removes the echo-request ICMP block. Block ping adds the echo-request ICMP block." />
            </div>
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
