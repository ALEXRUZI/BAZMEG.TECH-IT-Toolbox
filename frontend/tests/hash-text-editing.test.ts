// @vitest-environment node
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { displayedText, editText, replaceText } from '../src/tools/hash-calculator/text';
import { calculateHashes } from '../src/tools/hash-calculator/engine';

describe('selection-anchored exact text edits', () => {
  it.each([
    ['A\r', 'A\n\n', 2, 2, 'insertLineBreak'],
    ['\rX\n', '\n\n', 1, 1, 'deleteContentForward'],
    ['\rX\n', '\n\n', 2, 2, 'deleteContentBackward'],
    ['\rX\n', '\n\n', 1, 2, 'deleteContentForward'],
    ['\rX\n', '\n\n\n', 1, 2, 'insertLineBreak'],
    ['A\r', 'A\n\n', 2, 2, 'insertCompositionText'],
  ])('rejects raw CR/LF coalescence for %j -> %j', (raw, next, start, end, inputType) => {
    expect(editText(String(raw), String(next), { start: Number(start), end: Number(end), inputType: String(inputType) })).toBeNull();
  });
  it.each([
    ['A\r', 2, 2, '\n'], ['X\n', 0, 1, '\r'], ['\rX\n', 1, 2, ''],
  ])('rejects paste boundary coalescence for %j', (raw, start, end, inserted) => {
    expect(replaceText(String(raw), Number(start), Number(end), String(inserted))).toBeNull();
  });
  it('accepts a separating Unicode character without changing preserved newlines', async () => {
    const raw = replaceText('A\r', 2, 2, '雪\n');
    expect(raw).toBe('A\r雪\n');
    expect(displayedText(raw!)).toBe('A\n雪\n');
    const digest = createHash('sha256').update(raw!).digest('hex');
    expect((await calculateHashes({ input: raw!, algorithms: ['sha256'] }, () => {})).digests.sha256).toBe(digest);
  });
  it('deletes the first visible newline, not the equal-looking CRLF at the end', async () => {
    const text = editText('\n\r\n', '\n', { start: 0, end: 0, inputType: 'deleteContentForward' });
    expect(text).toBe('\r\n');
    const digest = createHash('sha256').update(text!).digest('hex');
    expect(digest).toBe('7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6');
    expect((await calculateHashes({ input: text!, algorithms: ['sha256'] }, () => {})).digests.sha256).toBe(digest);
    expect(digest).not.toBe('01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b');
  });
  it.each([
    [0, '\r\n\r'], [1, '\n\r'], [2, '\n\r\n'],
  ])('deleting newline %i leaves its distinct neighbours intact', (position, expected) => {
    const start = Number(position);
    expect(editText('\n\r\n\r', '\n\n', { start, end: start, inputType: 'deleteContentForward' })).toBe(expected);
    expect(editText('\n\r\n\r', '\n\n', { start: start + 1, end: start + 1, inputType: 'deleteContentBackward' })).toBe(expected);
    expect(editText('\n\r\n\r', '\n\n', { start, end: start + 1, inputType: 'deleteByCut' })).toBe(expected);
  });
  it.each([
    [0, 'x\n\r\n\r'], [1, '\nx\r\n\r'], [2, '\n\r\nx\r'], [3, '\n\r\n\rx'],
  ])('inserts at cursor %i instead of guessing a matching prefix', (position, expected) => {
    const start = Number(position);
    const next = '\n\n\n'.slice(0, start) + 'x' + '\n\n\n'.slice(start);
    expect(editText('\n\r\n\r', next, { start, end: start, inputType: 'insertText' })).toBe(expected);
  });
  it('preserves repeated adjacent lines and UTF-16 selection offsets with Unicode', () => {
    expect(editText('雪😀same\r\nsame\nsame\r', '雪😀same\nsame\n', { start: 8, end: 13, inputType: 'deleteContentForward' })).toBe('雪😀same\r\nsame\r');
    expect(editText('😀\n\r\n雪', '😀界\n雪', { start: 2, end: 3, inputType: 'insertText' })).toBe('😀界\r\n雪');
  });
  it('maps paste replacements directly to raw ranges without normalizing inserted data', () => {
    expect(replaceText('😀\n\r\n雪\r', 2, 3, '\r\n\r\nLF\n')).toBe('😀\r\n\r\nLF\n\r\n雪\r');
    expect(displayedText('\n\r\n\r')).toBe('\n\n\n');
  });
  it('applies a known selection replacement even when the display does not change', () => {
    expect(editText('\n\r\n', '\n\n', { start: 1, end: 2, inputType: 'insertLineBreak' })).toBe('\n\n');
    expect(editText('\n\r\n', '\n\n', null)).toBeNull();
  });
  it('rejects unreliable ranges and ambiguous browser changes instead of normalizing them', () => {
    expect(editText('\n\r\n', '\n', null)).toBeNull();
    expect(editText('\n\r\n', 'x\n', { start: 2, end: 2, inputType: 'insertText' })).toBeNull();
    expect(editText('\n\r\n', '\n', { start: 0, end: 0, inputType: 'historyUndo' })).toBeNull();
    expect(editText('\n\r\n', '', null)).toBe('');
    expect(editText('abc', 'ab', null)).toBe('ab');
  });
});
