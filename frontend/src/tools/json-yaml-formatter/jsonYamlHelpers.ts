export const MAX_FORMATTER_INPUT = 1_000_000;
export const MAX_JSON_DEPTH = 128;
export const MAX_FORMATTER_OUTPUT = 4_000_000;

const yamlUnsupported = 'Safe YAML formatting is unavailable: this lightweight formatter supports only simple mappings/sequences and single-line scalars, not block scalars, multiline values, flow collections, anchors, aliases, tags or directives.';
const tooLarge = 'Input exceeds the browser formatter limit of 1,000,000 characters.';
const failure = (error: string) => ({ output: '', error });

/** Source-token formatting only. JSON.parse validates syntax; its values never become output. */
export function formatJsonLossless(value: string, indent: 2 | 4 = 2) {
  if (value.length > MAX_FORMATTER_INPUT) return failure(tooLarge);
  const parts: string[] = [];
  let length = 0;
  let depth = 0;
  let previous = '';
  const whitespace = (char: string) => char === ' ' || char === '\t' || char === '\r' || char === '\n';
  const append = (part: string) => {
    length += part.length;
    if (length > MAX_FORMATTER_OUTPUT) throw new Error('Formatted output exceeds the browser limit of 4,000,000 characters.');
    parts.push(part);
  };
  const newline = () => append(`\n${' '.repeat(depth * indent)}`);

  try {
    for (let index = 0; index < value.length;) {
      if (whitespace(value[index])) { index += 1; continue; }
      const start = index;
      const char = value[index++];
      if (char === '"') {
        // Escaped quotes and punctuation stay inside their original source span.
        while (index < value.length) {
          const next = value[index++];
          if (next === '\\') index += 1;
          else if (next === '"') break;
        }
        append(value.slice(start, index));
      } else if (char === '{' || char === '[') {
        depth += 1;
        if (depth > MAX_JSON_DEPTH) return failure('JSON nesting exceeds the browser limit of 128 levels.');
        append(char);
        let next = index;
        while (next < value.length && whitespace(value[next])) next += 1;
        if (value[next] !== (char === '{' ? '}' : ']')) newline();
      } else if (char === '}' || char === ']') {
        depth -= 1;
        if (depth < 0) return failure('Invalid JSON syntax. Check commas, colons, strings and values.');
        if (previous !== '{' && previous !== '[') newline();
        append(char);
      } else if (char === ',') {
        append(','); newline();
      } else if (char === ':') {
        append(': ');
      } else {
        while (index < value.length && !whitespace(value[index]) && !'{}[],:"'.includes(value[index])) index += 1;
        append(value.slice(start, index));
      }
      previous = char;
    }
    // Never serialize this result: numbers may overflow or round, and keys may repeat.
    try { JSON.parse(value); } catch { return failure('Invalid JSON syntax. Check commas, colons, strings and values.'); }
    return { output: parts.join(''), error: '' };
  } catch (error) {
    return failure(error instanceof Error ? error.message : 'JSON formatting is unavailable.');
  }
}

/** Deliberately restricted YAML subset, not a YAML syntax validator. */
export function formatYamlLite(value: string) {
  if (value.length > MAX_FORMATTER_INPUT) return failure(tooLarge);
  const output: string[] = [];
  const levels: { indent: number; kind: string }[] = [];
  let previousIndent = -1;
  let allowsChild = true;

  for (const original of value.replace(/\r\n?/g, '\n').split('\n')) {
    // Only ASCII spaces are presentation indentation/trailing whitespace here.
    // Unicode whitespace can be scalar data (or a YAML-version-dependent break).
    if (/[\u0085\u2028\u2029]/.test(original)) return failure(yamlUnsupported);
    let end = original.length;
    while (end > 0 && original[end - 1] === ' ') end -= 1;
    const line = original.slice(0, end);
    let indent = 0;
    while (line[indent] === ' ') indent += 1;
    const content = line.slice(indent);
    if (!content) {
      if (output.length && output[output.length - 1] !== '') output.push('');
      continue;
    }
    if (content.startsWith('#')) { output.push(line); continue; }
    if (/^\s*\t/.test(line)) return failure('YAML indentation should use spaces, not tabs.');
    if ((content === '---' || content === '...') && indent === 0) {
      levels.length = 0; previousIndent = -1; allowsChild = true;
      output.push(line); continue;
    }
    const mapping = /^([a-zA-Z0-9_][a-zA-Z0-9_.-]*):(?: +([^\n]*))?$/.exec(content);
    const sequence = /^-(?: +([^\n]*))?$/.exec(content);
    if (!mapping && !sequence) return failure(yamlUnsupported);
    let scalar = (mapping ? mapping[2] : sequence?.[1]) ?? '';
    // Locate comments outside quotes, preserving every character inside quotes.
    let quote = '';
    for (let index = 0; index < scalar.length; index += 1) {
      const char = scalar[index];
      if (quote === '"' && char === '\\') { index += 1; continue; }
      if (quote === "'" && char === "'" && scalar[index + 1] === "'") { index += 1; continue; }
      if (char === quote) quote = '';
      else if (!quote && (char === '"' || char === "'")) quote = char;
      else if (!quote && char === '#' && (index === 0 || scalar[index - 1] === ' ')) {
        scalar = scalar.slice(0, index).trimEnd(); break;
      }
    }
    let supported = !scalar || /^[a-zA-Z0-9_+~-][a-zA-Z0-9_ .\/+~-]*$/.test(scalar);
    if (scalar.startsWith("'")) supported = /^'(?:[^']|'')*'$/.test(scalar);
    if (scalar.startsWith('"')) {
      try { supported = typeof JSON.parse(scalar) === 'string'; } catch { supported = false; }
    }
    if (!supported || quote) return failure(yamlUnsupported);

    // A deeper line after a scalar could be a folded plain-scalar continuation.
    // Only empty mapping/sequence entries may introduce a child collection.
    if (indent > previousIndent && !allowsChild) return failure(yamlUnsupported);
    while (levels.length && levels[levels.length - 1].indent > indent) levels.pop();
    const kind = mapping ? 'mapping' : 'sequence';
    const level = levels[levels.length - 1];
    if (level && (indent < level.indent || (indent === level.indent && kind !== level.kind))) return failure(yamlUnsupported);
    if (!level || indent > level.indent) levels.push({ indent, kind });
    previousIndent = indent;
    allowsChild = !scalar;
    output.push(line);
  }
  while (output[output.length - 1] === '') output.pop();
  return { output: output.join('\n'), error: '' };
}
