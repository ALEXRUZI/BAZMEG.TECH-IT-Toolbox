export function Hero() {
  return (
    <section className="relative overflow-hidden rounded-3xl border border-green-400/35 bg-gradient-to-br from-green-900/80 via-emerald-950 to-zinc-950 p-6 shadow-2xl shadow-green-950/50 sm:p-8">
      <a
        className="absolute right-4 top-4 inline-flex size-12 items-center justify-center rounded-2xl border border-emerald-400/35 bg-zinc-950/45 text-emerald-200 transition hover:border-emerald-300 hover:bg-emerald-500/15 sm:right-6 sm:top-6 sm:size-14"
        href="https://github.com/ALEXRUZI/BAZMEG.TECH-IT-Toolbox"
        target="_blank"
        rel="noreferrer"
        aria-label="GitHub project"
        title="GitHub project"
      >
        <svg aria-hidden="true" className="size-7 sm:size-8" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 2C6.48 2 2 6.58 2 12.22c0 4.5 2.87 8.32 6.84 9.67.5.09.68-.22.68-.49v-1.9c-2.78.62-3.37-1.22-3.37-1.22-.45-1.18-1.11-1.49-1.11-1.49-.91-.64.07-.63.07-.63 1 .07 1.53 1.06 1.53 1.06.9 1.56 2.35 1.11 2.92.85.09-.66.35-1.11.63-1.37-2.22-.26-4.56-1.14-4.56-5.06 0-1.12.39-2.03 1.03-2.75-.1-.26-.45-1.3.1-2.71 0 0 .84-.28 2.75 1.05A9.28 9.28 0 0 1 12 6.9c.85 0 1.7.12 2.5.34 1.9-1.33 2.74-1.05 2.74-1.05.55 1.41.2 2.45.1 2.71.64.72 1.03 1.63 1.03 2.75 0 3.93-2.34 4.8-4.57 5.05.36.32.68.94.68 1.9v2.8c0 .27.18.59.69.49A10.1 10.1 0 0 0 22 12.22C22 6.58 17.52 2 12 2Z" />
        </svg>
      </a>
      <div>
        <div>
          <div className="mt-3 max-w-5xl pr-14 sm:pr-20">
            <h2 className="max-w-3xl text-3xl font-bold tracking-tight sm:text-5xl">
              Useful sysadmin tools for real infrastructure work.
            </h2>
          </div>
          <p className="mt-4 max-w-2xl text-base leading-7 text-zinc-300">
            Generate firewall rules, cron schedules, permissions, and other admin snippets with validation built in before
            you paste anything into a terminal.
          </p>
        </div>
      </div>
    </section>
  );
}
