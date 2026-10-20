import { useEffect, useState } from 'react';

export function BackToTopButton() {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const updateVisibility = () => setIsVisible(window.scrollY > 500);

    updateVisibility();
    window.addEventListener('scroll', updateVisibility, { passive: true });

    return () => window.removeEventListener('scroll', updateVisibility);
  }, []);

  if (!isVisible) {
    return null;
  }

  return (
    <button
      className="fixed bottom-5 right-5 z-40 rounded-full border border-emerald-500/35 bg-zinc-950/90 px-4 py-2 text-sm font-semibold text-emerald-200 shadow-xl shadow-black/40 backdrop-blur transition hover:border-emerald-400 hover:bg-emerald-500/15"
      type="button"
      onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
    >
      Back to top
    </button>
  );
}
