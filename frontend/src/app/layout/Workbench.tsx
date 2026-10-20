import { renderTool } from '../renderTool';
import type { Tool } from '../toolTypes';
import { EmptyWorkbench } from './EmptyWorkbench';

export function Workbench({ selectedTool }: { selectedTool: Tool | null }) {
  if (!selectedTool) {
    return <EmptyWorkbench />;
  }

  return <section className="min-w-0">{renderTool(selectedTool)}</section>;
}
