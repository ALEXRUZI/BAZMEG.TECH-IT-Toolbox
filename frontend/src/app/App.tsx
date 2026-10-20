import { useState } from 'react';

import { BackToTopButton } from './layout/BackToTopButton';
import { Header } from './layout/Header';
import { Hero } from './layout/Hero';
import { ToolList } from './layout/ToolList';
import { Workbench } from './layout/Workbench';
import { tools } from './toolRegistry';
import type { ToolId } from './toolTypes';

export function App() {
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

export default App;
