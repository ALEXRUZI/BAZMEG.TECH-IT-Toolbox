import { useState } from 'react';

import { CommandBlock } from '../../components/CommandBlock';
import { Field, Label, Panel, inputClass, FieldInput, FieldSelect, FieldError } from '../../components/Panel';
import { clearExampleValue, restoreExampleValue } from '../../components/inputExamples';
import { CommonPortsHint } from '../firewall-shared/CommonPortsHint';
import { firewallExamples, validateIpv4Cidr, validatePort } from '../firewall-shared/firewallHelpers';

export function NftablesGenerator() {
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
              <Label>Chain</Label>
              <FieldSelect className={inputClass()} value={chain} onChange={(event) => setChain(event.target.value)}>
                <option>input</option>
                <option>forward</option>
                <option>output</option>
              </FieldSelect>
            </Field>
            <Field>
              <Label>Action</Label>
              <FieldSelect className={inputClass()} value={action} onChange={(event) => setAction(event.target.value)}>
                <option>accept</option>
                <option>drop</option>
                <option>reject</option>
              </FieldSelect>
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
