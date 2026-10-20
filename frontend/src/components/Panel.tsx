import { createContext, useContext, useId, useState } from 'react';
import type { ComponentProps, ReactNode } from 'react';

export function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <article className="min-w-0 max-w-full rounded-3xl border border-emerald-500/15 bg-zinc-900/70 p-5 text-zinc-100 shadow-xl shadow-black/30">
      <h2 className="text-xl font-semibold text-white">{title}</h2>
      <div className="mt-5 min-w-0">{children}</div>
    </article>
  );
}

type FieldMetadata = { id: string; error?: ReactNode; description?: ReactNode };
const FieldContext = createContext<FieldMetadata | null>(null);

export function Label({ children, htmlFor, className = '' }: { children: ReactNode; htmlFor?: string; className?: string }) {
  const field = useContext(FieldContext);
  return (
    <label htmlFor={htmlFor ?? field?.id} className={`text-sm font-medium text-zinc-300 ${className}`}>
      {children}
    </label>
  );
}

// One labeled control per Field. Groups use a fieldset and nested Fields instead.
export function Field({ children, id, error, description }: { children: ReactNode } & Partial<FieldMetadata>) {
  const generatedId = useId();
  return (
    <FieldContext.Provider value={{ id: id ?? generatedId, error, description }}>
      <div className="space-y-2">{children}</div>
    </FieldContext.Provider>
  );
}

function useFieldControl(props: Pick<ComponentProps<'input'>, 'id' | 'aria-describedby' | 'aria-invalid'>) {
  const field = useContext(FieldContext);
  return {
    id: props.id ?? field?.id,
    'aria-invalid': props['aria-invalid'] ?? (field?.error ? true : undefined),
    'aria-describedby': [
      props['aria-describedby'],
      field?.error && `${field.id}-error`,
      field?.description && `${field.id}-description`,
    ].filter(Boolean).join(' ') || undefined,
  };
}

export function FieldInput(props: ComponentProps<'input'>) {
  const association = useFieldControl(props);
  return <input {...props} {...association} />;
}

export function FieldSelect(props: ComponentProps<'select'>) {
  const association = useFieldControl(props);
  return <select {...props} {...association} />;
}

export function FieldTextarea(props: ComponentProps<'textarea'>) {
  const association = useFieldControl(props);
  return <textarea {...props} {...association} />;
}

export function FieldError({ className = '' }: { className?: string }) {
  const field = useContext(FieldContext);
  return field?.error ? <p id={`${field.id}-error`} className={`text-xs leading-5 text-red-300 ${className}`}>{field.error}</p> : null;
}

export function FieldDescription({ className = 'text-zinc-400' }: { className?: string }) {
  const field = useContext(FieldContext);
  return field?.description ? <p id={`${field.id}-description`} className={`text-xs leading-5 ${className}`}>{field.description}</p> : null;
}

export function HelpTooltip({ text, label }: { text: string; label: string }) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const [hovered, setHovered] = useState(false);
  const [focused, setFocused] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const visible = !dismissed && (open || hovered || focused);
  return (
    <span
      className="relative inline-flex"
      onMouseEnter={() => { setHovered(true); setDismissed(false); }}
      onMouseLeave={() => setHovered(false)}
    >
      <button
        type="button"
        aria-label={label}
        aria-describedby={id}
        aria-expanded={visible}
        aria-controls={id}
        onFocus={() => { setFocused(true); setDismissed(false); }}
        // Keyboard blur must win over a pointer that is still hovering here.
        // A fresh mouse entry, focus, or activation can clear dismissal again.
        onBlur={() => { setFocused(false); setOpen(false); setDismissed(true); }}
        onClick={() => { setOpen(!open); setDismissed(open); }}
        onKeyDown={(event) => { if (event.key === 'Escape') { setOpen(false); setDismissed(true); } }}
        className="inline-flex size-5 items-center justify-center rounded-full border border-white/15 bg-zinc-950 text-xs font-bold text-zinc-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-emerald-400"
      >
        ?
      </button>
      <span id={id} className={`absolute bottom-full left-1/2 z-10 w-64 -translate-x-1/2 rounded-xl border border-white/10 bg-zinc-950 p-3 text-xs font-normal leading-5 text-zinc-300 shadow-xl shadow-black/30 ${visible ? 'block' : 'hidden'}`}>
        {text}
      </span>
    </span>
  );
}

export function inputClass(hasError = false, isMuted = false) {
  const borderClass = hasError ? 'border-red-400/60 focus:border-red-400' : 'border-white/10 focus:border-emerald-500';
  const textClass = isMuted ? 'text-zinc-400' : 'text-zinc-100';

  return `w-full rounded-xl border ${borderClass} bg-zinc-950 px-3 py-2 text-sm ${textClass} outline-none transition`;
}

export function ExampleTextInput({
  value,
  example,
  hasError = false,
  onChange,
  ...props
}: {
  value: string;
  example: string;
  hasError?: boolean;
  onChange: (value: string) => void;
  id?: string;
  'aria-describedby'?: string;
}) {
  const [isFocused, setIsFocused] = useState(false);
  const isShowingExample = !isFocused && !value;

  return (
    <FieldInput
      {...props}
      aria-invalid={hasError || undefined}
      className={inputClass(hasError, isShowingExample)}
      value={isShowingExample ? example : value}
      onFocus={() => setIsFocused(true)}
      onChange={(event) => onChange(event.target.value)}
      onBlur={() => setIsFocused(false)}
    />
  );
}

export function ResultItem({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div className="min-w-0 rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500">{label}</p>
      <p className="mt-2 break-words font-mono text-sm text-zinc-100 [overflow-wrap:anywhere]">{value || '-'}</p>
    </div>
  );
}

export function ResultBlock({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div className="min-w-0 rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500">{label}</p>
      <pre className="mt-2 whitespace-pre-wrap break-words font-mono text-sm leading-6 text-zinc-100 [overflow-wrap:anywhere]">
        {value || '-'}
      </pre>
    </div>
  );
}
