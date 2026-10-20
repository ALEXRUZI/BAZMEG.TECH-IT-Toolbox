import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { JsonYamlFormatter } from '../src/tools/json-yaml-formatter/JsonYamlFormatter';
import { formatJsonLossless, formatYamlLite, MAX_FORMATTER_INPUT, MAX_JSON_DEPTH } from '../src/tools/json-yaml-formatter/jsonYamlHelpers';

const jsonSample = '{"name":"it-toolbox","enabled":true,"tools":["json","yaml"]}';
const yamlSample = 'name: it-toolbox\nenabled: true\ntools:\n  - json\n  - yaml';
function edit(value: string) { fireEvent.change(screen.getByRole('textbox'), { target: { value } }); }
function output() { return document.querySelector('pre')?.textContent; }

describe('JSON/YAML formatter regression', () => {
  it.each([
    ['{"a":1}', '{\n  "a": 1\n}'],
    ['[1,true,null,"text"]', '[\n  1,\n  true,\n  null,\n  "text"\n]'],
    ['{"a":[{"b":false},null]}', '{\n  "a": [\n    {\n      "b": false\n    },\n    null\n  ]\n}'],
    ['{}', '{}'], ['[]', '[]'], ['"hello"', '"hello"'], ['42.5', '42.5'], ['true', 'true'], ['null', 'null'],
    ['{"text":"\u017dlu\u0165ou\u010dk\u00fd \ud83d\ude00"}', '{\n  "text": "\u017dlu\u0165ou\u010dk\u00fd \ud83d\ude00"\n}'],
    ['{"escape":"line\\nquote\\\"slash\\\\"}', '{\n  "escape": "line\\nquote\\\"slash\\\\"\n}'],
  ])('formats JSON %s with independent expected output', (input, expected) => {
    render(<JsonYamlFormatter />); edit(input); expect(output()).toBe(expected);
  });

  it('keeps two-space defaults and supports four-space indentation', () => {
    render(<JsonYamlFormatter />);
    expect(screen.getByRole('textbox')).toHaveValue(jsonSample);
    expect(screen.getByRole('combobox')).toHaveValue('2');
    edit('{"a":{"b":1}}');
    fireEvent.change(screen.getByRole('combobox'), { target: { value: '4' } });
    expect(output()).toBe('{\n    "a": {\n        "b": 1\n    }\n}');
  });

  it.each(['', ' ', '{', '[1,]', '{"a":undefined}', '{"a":1,}', '[1 2]', '{"a" 1}', '01', '1.', '+1', 'NaN', 'Infinity', '"unfinished', '"bad\\x"', '"raw\nnewline"'])('rejects JSON %j and recovers without stale output', (value) => {
    render(<JsonYamlFormatter />); edit(value);
    expect(screen.getByText('Fix the JSON input before using the formatted output.')).toBeInTheDocument();
    expect(output()).toBeUndefined();
    expect(screen.queryByRole('button', { name: /copy/i })).toBeNull();
    edit('{"ok":true}'); expect(output()).toBe('{\n  "ok": true\n}');
  });

  it.each([
    [yamlSample, yamlSample],
    ['\r\n\r\nname: test  \r\nroot:   \r\n  child: yes   \r\n\r\n\r\nnext: 1 \r\n\r\n', 'name: test\nroot:\n  child: yes\n\nnext: 1'],
    ['a: 1\rb: 2\n', 'a: 1\nb: 2'],
    ['---\n # odd comment indentation is allowed\nchild: 1\n...\n', '---\n # odd comment indentation is allowed\nchild: 1\n...'],
    ['\n   \n', ''],
    ['  root:\n    child: yes', '  root:\n    child: yes'],
    ['root:\n child: yes', 'root:\n child: yes'],
    ['quoted: "space  and # text"  \nother: \'it\'\'s fine  \'  ', 'quoted: "space  and # text"\nother: \'it\'\'s fine  \''],
    ['root: # comment  \n  - first  \n  - second\n', 'root: # comment\n  - first\n  - second'],
  ])('cleans supported YAML whitespace without extending parsing', (input, expected) => {
    render(<JsonYamlFormatter />); fireEvent.click(screen.getByRole('button', { name: 'YAML' }));
    edit(input); expect(output()).toBe(expected); expect(screen.queryByRole('combobox')).toBeNull();
  });

  it.each([
    ['\tkey: value', 'YAML indentation should use spaces, not tabs.'],
  ])('preserves YAML error messages and recovery', (value, message) => {
    render(<JsonYamlFormatter />); fireEvent.click(screen.getByRole('button', { name: 'YAML' })); edit(value);
    expect(screen.getByText(message)).toBeInTheDocument();
    expect(screen.getByText('Fix the YAML input before using the formatted output.')).toBeInTheDocument();
    expect(output()).toBeUndefined(); edit(yamlSample); expect(output()).toBe(yamlSample);
  });

  it('resets samples on mode switches, restores blank input and preserves indentation selection', () => {
    render(<JsonYamlFormatter />);
    fireEvent.change(screen.getByRole('combobox'), { target: { value: '4' } });
    edit('{"custom":1}'); fireEvent.click(screen.getByRole('button', { name: 'YAML' }));
    expect(screen.getByRole('textbox')).toHaveValue(yamlSample);
    fireEvent.focus(screen.getByRole('textbox')); expect(screen.getByRole('textbox')).toHaveValue('');
    fireEvent.blur(screen.getByRole('textbox')); expect(screen.getByRole('textbox')).toHaveValue(yamlSample);
    fireEvent.click(screen.getByRole('button', { name: 'JSON' }));
    expect(screen.getByRole('textbox')).toHaveValue(jsonSample); expect(screen.getByRole('combobox')).toHaveValue('4');
    fireEvent.focus(screen.getByRole('textbox')); expect(output()).toBeUndefined();
    fireEvent.blur(screen.getByRole('textbox')); expect(screen.getByRole('textbox')).toHaveValue(jsonSample);
  });
});

describe('lossless source tokens and resource limits', () => {
  const numbers = ['9007199254740993', '-9007199254740993', '18446744073709551615', '1e400', '1e-4000', '-0', '-0.0', '0.0000000000000000000000001', '1.23456789012345678901234567890123456789', '2E+123', '-3e-456', '9'.repeat(10_000)];
  it.each(numbers)('preserves an exact numeric token (case %#)', (token) => {
    const input = `{"n":${token}}`;
    const expected = `{\n  "n": ${token}\n}`;
    expect(formatJsonLossless(input)).toEqual({ output: expected, error: '' });
    expect(formatJsonLossless(expected).output).toBe(expected);
    expect(formatJsonLossless(token).output).toBe(token);
  });
  it('preserves nested numeric formats, duplicate keys and original integer-like key order', () => {
    const input = '{"2":-0,"1":1e400,"2":[9007199254740993,{"d":0.123456789012345678901,"n":-1E+400}]}';
    const expected = '{\n  "2": -0,\n  "1": 1e400,\n  "2": [\n    9007199254740993,\n    {\n      "d": 0.123456789012345678901,\n      "n": -1E+400\n    }\n  ]\n}';
    expect(formatJsonLossless(input).output).toBe(expected);
    expect(formatJsonLossless(expected).output).toBe(expected);
  });
  it('preserves original string escapes and punctuation independently of structure', () => {
    const token = '"{,}: [ ] \\u0041 \\n \\t \\" \\\\ Unicode ž 😀"';
    const input = `{"s":${token}}`;
    const formatted = formatJsonLossless(input).output;
    expect(formatted).toBe(`{\n  "s": ${token}\n}`);
    // Parsing here is an independent string-value oracle only, never a numeric oracle.
    expect(JSON.parse(formatted).s).toBe(JSON.parse(input).s);
    expect(formatJsonLossless(formatted).output).toBe(formatted);
  });
  it('bounds input, depth and expanded output without recursion or partial results', () => {
    expect(formatJsonLossless(' '.repeat(MAX_FORMATTER_INPUT + 1)).error).toContain('1,000,000');
    expect(formatYamlLite(' '.repeat(MAX_FORMATTER_INPUT + 1)).output).toBe('');
    const nested = '['.repeat(MAX_JSON_DEPTH) + '0' + ']'.repeat(MAX_JSON_DEPTH);
    expect(formatJsonLossless(nested).error).toBe('');
    expect(formatJsonLossless(`[${nested}]`)).toEqual({ output: '', error: 'JSON nesting exceeds the browser limit of 128 levels.' });
    const expansion = '['.repeat(128) + Array(10_000).fill('0').join(',') + ']'.repeat(128);
    expect(formatJsonLossless(expansion, 4)).toEqual({ output: '', error: 'Formatted output exceeds the browser limit of 4,000,000 characters.' });
    expect(formatJsonLossless('{}').output).toBe('{}');
  });
});

describe('conservative YAML scalar integrity', () => {
  const unsupported = [
    ...['|', '>', '|-', '|+', '>-', '>+', '|2', '>2-', '|+2', '>2+'].map((indicator) => `message: ${indicator} # scalar\n  first line  \n\n\n  third line\n\n`),
    'root:\n  message: |\n    text  \n', '- |\n  text\n', '- message: >\n    text\n',
    'message: |+\r\n  first  \r\n\r\n', 'message: text\n  continuation', 'message: text\n  - continuation',
    'quoted: "first\n  second"', "quoted: 'first\n\n  second'", 'key: text\tvalue',
    'key: &anchor value\nother: *anchor', 'key: !!str true', '%YAML 1.2\n---\na: 1', 'not: [valid YAML', 'flow: {a: 1}',
    'key:\n \u00a0\n', '# comment\u0085message: |\u0085  text  ', 'key: "line\u2028break"',
  ];
  it.each(unsupported)('refuses uncertain YAML (case %#) with no copyable or stale output and recovers', (input) => {
    render(<JsonYamlFormatter />);
    fireEvent.click(screen.getByRole('button', { name: 'YAML' })); edit(input);
    expect(screen.getByRole('alert')).toHaveTextContent('Safe YAML formatting is unavailable: this lightweight formatter supports only simple mappings/sequences and single-line scalars, not block scalars, multiline values, flow collections, anchors, aliases, tags or directives.');
    expect(output()).toBeUndefined();
    expect(screen.queryByRole('button', { name: /copy/i })).toBeNull();
    edit(yamlSample); expect(output()).toBe(yamlSample);
  });
  it.each([
    '\r\nroot:  \r\n child: yes  \r\n\r\n\r\nother: null  \r\n',
    '---\na: 2026-10-10\n...\n---\na: true\n',
    'a: "trailing  "  \nb: \'trailing  \'  \nc: "quote\\\" and slash\\\\"\n',
    'root:\n   - one\n   - two\n', '# comment\n\nname: test\n',
  ])('is idempotent on the supported subset (case %#)', (input) => {
    const result = formatYamlLite(input);
    expect(result.error).toBe('');
    expect(formatYamlLite(result.output)).toEqual(result);
  });
});
