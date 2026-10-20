import type { ButtonHTMLAttributes, ReactNode } from 'react';

type CopyButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  children: ReactNode;
};

export function CopyButton({ children, className, type = 'button', ...props }: CopyButtonProps) {
  return (
    <button
      className={
        className ??
        'rounded-lg border border-emerald-500/30 px-3 py-1 text-xs font-semibold text-emerald-300 transition hover:border-emerald-400 hover:bg-emerald-500/10'
      }
      type={type}
      {...props}
    >
      {children}
    </button>
  );
}
