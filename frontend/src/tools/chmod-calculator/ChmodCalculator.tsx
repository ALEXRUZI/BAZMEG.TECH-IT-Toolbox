import { useId, useState } from 'react';

import { CommandBlock } from '../../components/CommandBlock';
import { Field, Label, Panel, inputClass, FieldTextarea } from '../../components/Panel';
import { clearExampleValue } from '../../components/inputExamples';

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

export function ChmodCalculator() {
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
  const pathError = !path ? 'Enter a path to generate a chmod command.'
    : path.includes('\0') ? 'A Linux filename cannot contain a NUL character.' : null;
  const errorId = useId();
  const command = pathError ? null : `chmod ${mode} -- '${path.replace(/'/g, "'\\''")}'`;

  return (
    <Panel title="chmod calculator">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Choose read, write, and execute permissions for owner, group, and others to generate a numeric chmod command.
      </p>
      <div className="mt-5 grid gap-4 lg:grid-cols-[minmax(0,1fr)_240px]">
        <div>
          <Field>
            <Label>Path</Label>
            <FieldTextarea
              aria-invalid={Boolean(pathError)}
              aria-describedby={pathError ? errorId : undefined}
              aria-label="Path"
              rows={1}
              className={inputClass(false, path === '/var/www/html')}
              value={path}
              onChange={(event) => setPath(event.target.value)}
              onFocus={() => clearExampleValue(path, '/var/www/html', setPath)}
              onBlur={() => { if (path === '') setPath('/var/www/html'); }}
            />
          </Field>
          <div className="mt-5 grid gap-4 md:grid-cols-3">
            {(['owner', 'group', 'others'] as PermissionGroup[]).map((group) => (
              <div key={group} role="group" aria-labelledby={`${errorId}-${group}`} className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
                <h3 id={`${errorId}-${group}`} className="text-sm font-semibold capitalize text-zinc-200">{group}</h3>
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
          {command !== null ? <CommandBlock>{command}</CommandBlock> : (
            <p id={errorId} role="status" className="mt-4 text-sm text-zinc-300">{pathError}</p>
          )}
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
