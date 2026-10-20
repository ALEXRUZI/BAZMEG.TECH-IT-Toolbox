import { useId, useState } from 'react';

export function SshOutputOption({ label, explanation, disabled, checked, onChange }: {
  label: string; explanation: string; disabled: boolean; checked: boolean; onChange: (checked: boolean) => void;
}) {
  const descriptionId = useId();
  const [open, setOpen] = useState(false), [hovered, setHovered] = useState(false), [focused, setFocused] = useState(false), [dismissed, setDismissed] = useState(false);
  const visible = !dismissed && (open || hovered || focused);
  // One hover boundary includes the native disabled control, label, button and tooltip.
  // Ignore touch pointers so tapping the information button remains a true toggle.
  return <div className="relative flex max-w-full items-center gap-2 text-sm"
    onPointerEnter={event => { if (explanation && event.pointerType !== 'touch') { setHovered(true); setDismissed(false); } }}
    onPointerLeave={event => { if (event.pointerType !== 'touch') setHovered(false); }}>
    <label className="flex min-w-0 items-center gap-2">
      <input type="checkbox" disabled={disabled} checked={!disabled && checked} aria-describedby={explanation ? descriptionId : undefined} onChange={event => onChange(event.target.checked)} />
      <span className={explanation ? 'line-through opacity-60' : undefined}>{label}</span>
    </label>
    {explanation && <>
      <span className="inline-flex">
        <button type="button" aria-label={`Why ${label} is unavailable`} aria-describedby={descriptionId} aria-expanded={visible} aria-controls={descriptionId}
          onFocus={() => { setFocused(true); setDismissed(false); }}
          onBlur={() => { setFocused(false); setOpen(false); setDismissed(true); }}
          onClick={() => { setOpen(!open); setDismissed(open); }}
          onKeyDown={event => { if (event.key === 'Escape') { setOpen(false); setDismissed(true); } }}
          className="inline-flex size-6 shrink-0 items-center justify-center rounded-full border border-white/15 bg-zinc-950 text-xs font-bold text-zinc-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-emerald-400">
          <span aria-hidden="true">i</span>
        </button>
      </span>
      <span id={descriptionId} role="tooltip" hidden={!visible}
        className="absolute bottom-full left-0 z-10 w-64 max-w-full rounded-xl border border-white/10 bg-zinc-950 p-3 text-xs font-normal leading-5 text-zinc-300 shadow-xl shadow-black/30">
        {explanation}
      </span>
    </>}
  </div>;
}
