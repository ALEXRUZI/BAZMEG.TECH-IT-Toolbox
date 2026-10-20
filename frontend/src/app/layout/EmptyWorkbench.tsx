import { Panel } from '../../components/Panel';

export function EmptyWorkbench() {
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
