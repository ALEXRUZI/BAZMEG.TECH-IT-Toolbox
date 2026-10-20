import { Panel } from '../../components/Panel';
import type { Tool } from '../toolTypes';

export function PlannedTool({ tool }: { tool: Tool }) {
  return (
    <Panel title={tool.name}>
      <div className="rounded-2xl border border-amber-400/20 bg-amber-400/10 p-4 text-sm leading-6 text-amber-100">
        {tool.description} This UI is planned for a later version.
      </div>
    </Panel>
  );
}
