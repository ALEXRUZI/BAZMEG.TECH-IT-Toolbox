import { useCallback, useLayoutEffect, useRef, useState } from 'react';
import type { ClipboardEvent, CompositionEvent, FormEvent, KeyboardEvent } from 'react';
import { displayedText, editText, replaceText, type TextEdit } from './text';

type Snapshot = { text: string; start: number; end: number };
type Composition = { before: Snapshot; start: number; end: number };
const unsupported = 'This edit could not preserve both exact bytes and the intended display (a lone CR and LF can join into CRLF), or did not expose a reliable text range. The edit was not applied; original line endings are unchanged. Use a different edit or file mode for exact bytes.';
const HISTORY_LIMIT = 50;

export function useExactTextEditor(invalidate: () => void) {
  const [text, setText] = useState('');
  const [error, setError] = useState('');
  const [composing, setComposing] = useState(false);
  const [selectionVersion, setSelectionVersion] = useState(0);
  const raw = useRef('');
  const control = useRef<HTMLTextAreaElement | null>(null);
  const pending = useRef<(Snapshot & { edit: TextEdit }) | null>(null);
  const composition = useRef<Composition | null>(null);
  const undo = useRef<Snapshot[]>([]);
  const redo = useRef<Snapshot[]>([]);
  const selection = useRef<{ start: number; end: number } | null>(null);
  const beforeHandler = useRef<(event: InputEvent) => void>(() => {});
  const listener = useCallback((event: Event) => beforeHandler.current(event as InputEvent), []);
  const ref = useCallback((node: HTMLTextAreaElement | null) => {
    control.current?.removeEventListener('beforeinput', listener);
    control.current = node;
    node?.addEventListener('beforeinput', listener);
    pending.current = null;
    if (composition.current) setComposing(false);
    composition.current = null;
  }, [listener]);

  function snapshot(): Snapshot {
    return { text: raw.current, start: control.current?.selectionStart ?? 0, end: control.current?.selectionEnd ?? 0 };
  }
  function remember(before: Snapshot) {
    undo.current.push(before);
    if (undo.current.length > HISTORY_LIMIT) undo.current.shift();
    redo.current = [];
  }
  function publish(value: string, caret?: { start: number; end: number }) {
    invalidate();
    raw.current = value;
    setText(value);
    setError('');
    pending.current = null;
    selection.current = caret ?? null;
    if (caret) {
      // Equal-byte replacement/paste may still move the caret. Force the layout
      // restoration even when React would otherwise skip an unchanged value.
      setSelectionVersion((version) => version + 1);
      // Also restore synchronously when a rejected edit leaves state unchanged.
      if (control.current) {
        control.current.value = displayedText(value);
        control.current.setSelectionRange(caret.start, caret.end);
      }
    }
  }
  useLayoutEffect(() => {
    if (selection.current) {
      control.current?.setSelectionRange(selection.current.start, selection.current.end);
      selection.current = null;
    }
  }, [text, selectionVersion]);
  function history(direction: 'undo' | 'redo') {
    if (composition.current) return;
    const source = direction === 'undo' ? undo : redo;
    const target = direction === 'undo' ? redo : undo;
    const previous = source.current.pop();
    if (!previous) return;
    target.current.push(snapshot());
    publish(previous.text, previous);
  }
  beforeHandler.current = (event) => {
    if (event.inputType === 'historyUndo' || event.inputType === 'historyRedo') {
      if (event.cancelable) { event.preventDefault(); history(event.inputType === 'historyUndo' ? 'undo' : 'redo'); }
      else pending.current = null; // Non-cancelable native history is rejected below.
      return;
    }
    const before = snapshot();
    const range = composition.current && event.inputType === 'insertCompositionText' ? composition.current : before;
    const captured = { ...before, edit: { start: range.start, end: range.end, inputType: event.inputType } };
    pending.current = captured;
    // A cancelled beforeinput must not lend its range to a later range-less edit.
    // Keep it through the native editing task (browsers run microtask checkpoints
    // between event listeners), but expire it before a later user editing task.
    window.setTimeout(() => { if (pending.current === captured) pending.current = null; }, 0);
  };
  function onInput(event: FormEvent<HTMLTextAreaElement>) {
    const node = event.currentTarget;
    const native = event.nativeEvent as InputEvent;
    const before = pending.current;
    const next = ['historyUndo', 'historyRedo', 'insertFromPaste', 'insertFromDrop'].includes(native.inputType)
      ? null : editText(raw.current, node.value, before?.text === raw.current && before.edit.inputType === native.inputType ? before.edit : null);
    if (next === null) {
      const saved = before ?? snapshot();
      publish(raw.current, saved);
      setError(unsupported);
      return;
    }
    if (next !== raw.current) {
      if (!composition.current) remember(before ?? { text: raw.current, start: 0, end: displayedText(raw.current).length });
      else composition.current.end = composition.current.start + node.value.length - (displayedText(raw.current).length - (composition.current.end - composition.current.start));
      publish(next);
    }
    pending.current = null;
  }
  function onPaste(event: ClipboardEvent<HTMLTextAreaElement>) {
    event.preventDefault();
    if (composition.current) { setError('Finish text composition before pasting.'); return; }
    const before = snapshot();
    const pasted = event.clipboardData.getData('text/plain');
    const next = replaceText(raw.current, before.start, before.end, pasted);
    if (next === null) {
      publish(raw.current, before);
      setError(unsupported);
      return;
    }
    if (next !== raw.current) remember(before);
    const cursor = before.start + displayedText(pasted).length;
    publish(next, { start: cursor, end: cursor });
  }
  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if ((event.ctrlKey || event.metaKey) && !event.altKey && !event.nativeEvent.isComposing) {
      const key = event.key.toLowerCase();
      if (key === 'z' || key === 'y') {
        event.preventDefault();
        history(key === 'y' || event.shiftKey ? 'redo' : 'undo');
      }
    }
  }
  function onCompositionStart() {
    const before = snapshot();
    composition.current = { before, start: before.start, end: before.end };
    setComposing(true);
    invalidate();
  }
  function onCompositionEnd(_event: CompositionEvent<HTMLTextAreaElement>) {
    const current = composition.current;
    composition.current = null;
    setComposing(false);
    if (current && current.before.text !== raw.current) remember(current.before);
    pending.current = null;
  }
  function reset() {
    undo.current = []; redo.current = []; composition.current = null; setComposing(false);
    publish('', { start: 0, end: 0 });
  }
  return { text, error, reset, composing, props: {
    ref, value: displayedText(text), onInput, onChange: () => {}, onPaste, onKeyDown, onCompositionStart, onCompositionEnd,
    onDrop: (event: FormEvent<HTMLTextAreaElement>) => { event.preventDefault(); setError('Text dragging is not supported. Use selection and paste instead; original text is unchanged.'); },
  } };
}
