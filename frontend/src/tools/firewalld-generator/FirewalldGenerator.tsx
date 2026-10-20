import { useState } from 'react';

import { CommandBlock } from '../../components/CommandBlock';
import { Field, Label, Panel, inputClass, FieldInput, FieldSelect, FieldError } from '../../components/Panel';
import { clearExampleValue, restoreExampleValue } from '../../components/inputExamples';
import { CommonPortsHint } from '../firewall-shared/CommonPortsHint';
import { firewallExamples, validateIpv4Cidr, validatePort } from '../firewall-shared/firewallHelpers';
import { FirewalldZonesBlock } from './FirewalldZonesBlock';

export function FirewalldGenerator() {
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
  const unsupportedSourcePort = useSourcePort;
  const destinationClause = useDestination ? ` destination address="${destination.trim()}"` : '';
  const command =
    protocol === 'icmp'
      ? `sudo firewall-cmd ${
          mode === 'permanent' ? '--permanent ' : ''
        }--add-rich-rule='rule family="ipv4" source address="${source.trim()}"${destinationClause} protocol value="icmp" accept'`
      : `sudo firewall-cmd ${
          mode === 'permanent' ? '--permanent ' : ''
        }--add-rich-rule='rule family="ipv4" source address="${source.trim()}"${destinationClause} port port="${port.trim()}" protocol="${protocol}" accept'`;

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
              {protocol !== 'icmp' && useSourcePort && (
                <Field error={sourcePortError}>
                  <Label>Source port</Label>
                  <FieldInput
                    className={inputClass(Boolean(sourcePortError), sourcePort === firewallExamples.sourcePort)}
                    value={sourcePort}
                    onChange={(event) => setSourcePort(event.target.value)}
                    onFocus={() => clearExampleValue(sourcePort, firewallExamples.sourcePort, setSourcePort)}
                    onBlur={() => restoreExampleValue(sourcePort, firewallExamples.sourcePort, setSourcePort)}
                  />
                  <FieldError />
                </Field>
              )}
              {useDestination && (
                <Field error={destinationError}>
                  <Label>Destination IPv4</Label>
                  <FieldInput
                    className={inputClass(Boolean(destinationError), destination === firewallExamples.destination)}
                    value={destination}
                    onChange={(event) => setDestination(event.target.value)}
                    onFocus={() => clearExampleValue(destination, firewallExamples.destination, setDestination)}
                    onBlur={() => restoreExampleValue(destination, firewallExamples.destination, setDestination)}
                  />
                  <FieldError />
                </Field>
              )}
              {protocol !== 'icmp' && (
                <Field error={portError}>
                  <Label>Destination port</Label>
                  <FieldInput
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
                  <FieldError />
                </Field>
              )}
              <Field>
                <Label>Protocol</Label>
                <FieldSelect className={inputClass()} value={protocol} onChange={(event) => setProtocol(event.target.value)}>
                  <option>tcp</option>
                  <option>udp</option>
                  <option>icmp</option>
                </FieldSelect>
              </Field>
              <Field>
                <Label>Rule mode</Label>
                <FieldSelect
                  className={inputClass()}
                  value={mode}
                  onChange={(event) => setMode(event.target.value as 'runtime' | 'permanent')}
                >
                  <option value="permanent">Permanent</option>
                  <option value="runtime">Runtime</option>
                </FieldSelect>
              </Field>
            </div>
            <div className="mt-4 rounded-2xl border border-emerald-500/15 bg-emerald-500/10 p-4 text-sm leading-6 text-zinc-300">
              <span className="font-semibold text-zinc-100">Rule mode</span> controls the generated rich-rule command below.
              <span className="font-semibold text-emerald-300"> Permanent</span> saves the rule in firewalld config and needs
              reload to apply. <span className="font-semibold text-emerald-300">Runtime</span> applies now but is lost after
              firewalld reload or restart.
            </div>
            <label className="mt-4 flex items-center gap-3 text-sm font-medium text-zinc-300">
              <input
                checked={useSourcePort}
                className="size-4 accent-emerald-500"
                type="checkbox"
                onChange={(event) => setUseSourcePort(event.target.checked)}
              />
              Add source port (unsupported)
            </label>
            <label className="mt-4 flex items-center gap-3 text-sm font-medium text-zinc-300">
              <input
                checked={useDestination}
                className="size-4 accent-emerald-500"
                type="checkbox"
                onChange={(event) => setUseDestination(event.target.checked)}
              />
              Add destination IPv4
            </label>
            {unsupportedSourcePort && (
              <div role="status" className="mt-4 rounded-2xl border border-yellow-400/30 bg-yellow-400/10 p-4 text-sm leading-6 text-yellow-200">
                Source-port restrictions are unsupported in this generator. Firewalld rich rules cannot combine
                source-port with a destination-port or protocol element. No command or reload is generated.
                Uncheck the source-port option only if you intend to remove that restriction.
              </div>
            )}
            {sourceError || sourcePortError || portError || destinationError ? (
              <div className="mt-4 rounded-2xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-100">
                Fix the IPv4 address, CIDR prefix, or port before using the generated command.
              </div>
            ) : unsupportedSourcePort ? null : (
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
