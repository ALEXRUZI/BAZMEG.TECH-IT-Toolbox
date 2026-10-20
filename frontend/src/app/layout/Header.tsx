import { ToolboxIcon } from './ToolboxIcon';

export function Header() {
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
