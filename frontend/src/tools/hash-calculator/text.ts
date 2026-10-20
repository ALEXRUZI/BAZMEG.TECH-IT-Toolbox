export const displayedText = (text: string) => text.replace(/\r\n?/g, '\n');

// Textarea selections use UTF-16 offsets in the LF-normalized display.
export function textOffset(text: string, displayedOffset: number) {
  let original = 0;
  for (let displayed = 0; displayed < displayedOffset && original < text.length; displayed++) {
    original += text[original] === '\r' && text[original + 1] === '\n' ? 2 : 1;
  }
  return original;
}

export function replaceText(text: string, start: number, end: number, inserted: string) {
  const candidate = text.slice(0, textOffset(text, start)) + inserted + text.slice(textOffset(text, end));
  const displayed = displayedText(text);
  const proposed = displayed.slice(0, start) + displayedText(inserted) + displayed.slice(end);
  // Normalization is not compositional: a preserved lone CR can pair with an
  // inserted/surviving LF across the splice, removing a visible newline.
  return displayedText(candidate) === proposed ? candidate : null;
}

export type TextEdit = { start: number; end: number; inputType: string };

// Resolve the splice using the pre-input selection and the browser's edit
// direction, NOT equal-looking prefixes/suffixes. Validate the entire display
// against that splice before accepting it. null means insufficient information.
export function editText(previous: string, next: string, edit: TextEdit | null) {
  const displayed = displayedText(previous);
  if (!edit) {
    // With no CR there are no hidden newline distinctions to lose. Clearing
    // everything is also unambiguous. Otherwise fail closed, never guess.
    return !previous.includes('\r') || next === '' ? next : null;
  }
  let { start, end } = edit;
  if (start < 0 || end < start || end > displayed.length) return null;
  if (edit.inputType.startsWith('delete')) {
    if (start === end) {
      const removed = displayed.length - next.length;
      if (removed < 0) return null;
      if (edit.inputType.endsWith('Backward')) start -= removed;
      else if (edit.inputType.endsWith('Forward')) end += removed;
      else return null;
    }
  } else if (!['insertText', 'insertLineBreak', 'insertParagraph', 'insertCompositionText', 'insertFromComposition'].includes(edit.inputType)) return null;
  if (start < 0 || end > displayed.length) return null;
  const insertedLength = next.length - (displayed.length - (end - start));
  if (insertedLength < 0) return null;
  const inserted = next.slice(start, start + insertedLength);
  if (edit.inputType.startsWith('delete') && inserted) return null;
  if (displayed.slice(0, start) + inserted + displayed.slice(end) !== next) return null;
  const candidate = replaceText(previous, start, end, inserted);
  return candidate !== null && displayedText(candidate) === next ? candidate : null;
}
