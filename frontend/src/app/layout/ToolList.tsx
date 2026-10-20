import { useState } from 'react';

import { Field, FieldInput, Label, inputClass } from '../../components/Panel';
import { statusStyle, tools } from '../toolRegistry';
import type { Tool, ToolId } from '../toolTypes';

export function ToolList({
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
        <Field>
          <Label className="sr-only">Search tools</Label>
          <FieldInput
            className={inputClass()}
            placeholder="Search tools, tags, ports..."
            value={searchQuery}
            onChange={(event) => setSearchQuery(event.target.value)}
          />
        </Field>
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
