import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { EncoderTool } from '../src/tools/base64-url-encoder/EncoderTool';

const unicode = '\u017dlu\u0165ou\u010dk\u00fd k\u00f4\u0148 \ud83d\ude00';
const unicodeBase64 = 'xb1sdcWlb3XEjWvDvSBrw7TFiCDwn5iA';
const unicodeUrl = '%C5%BDlu%C5%A5ou%C4%8Dk%C3%BD%20k%C3%B4%C5%88%20%F0%9F%98%80';
function mode(value: string) { fireEvent.change(screen.getByRole('combobox'), { target: { value } }); }
function edit(value: string) { fireEvent.change(screen.getByRole('textbox'), { target: { value } }); }
function output() { return document.querySelector('pre')?.textContent; }

describe('Base64 / URL encoder regression', () => {
  it.each([
    ['base64-encode', 'Hello', 'SGVsbG8='], ['base64-decode', 'SGVsbG8=', 'Hello'],
    ['base64-encode', unicode, unicodeBase64], ['base64-decode', unicodeBase64, unicode],
    ['base64-encode', '\ud83d\ude00', '8J+YgA=='], ['base64-decode', '8J+YgA==', '\ud83d\ude00'],
    ['base64-decode', '  SGVsbG8=\n', 'Hello'],
    ['url-encode', 'a b?x=1&y=#/%', 'a%20b%3Fx%3D1%26y%3D%23%2F%25'],
    ['url-decode', 'a%20b%3Fx%3D1%26y%3D%23%2F%25', 'a b?x=1&y=#/%'],
    ['url-encode', unicode, unicodeUrl], ['url-decode', unicodeUrl, unicode],
    ['url-encode', "!'()*", "!'()*"], ['url-decode', 'a+b', 'a+b'],
    // Component encoding escapes URL delimiters, unlike encodeURI on a whole URL.
    ['url-encode', 'https://example.test/?q=a b', 'https%3A%2F%2Fexample.test%2F%3Fq%3Da%20b'],
    ['base64-encode', '', ''], ['base64-decode', '', ''], ['url-encode', '', ''], ['url-decode', '', ''],
  ])('%s uses independent expected bytes/text for %j', (selectedMode, input, expected) => {
    render(<EncoderTool />); mode(selectedMode); edit(input); expect(output()).toBe(expected);
  });

  it.each([
    ['base64-decode', '!!!', 'Input is not valid Base64.'],
    ['base64-decode', 'A', 'Input is not valid Base64.'],
    ['base64-decode', '/w==', 'Input is not valid Base64.'],
    ['base64-decode', 'wyg=', 'Input is not valid Base64.'],
    ['url-decode', '%', 'Input is not valid URL-encoded text.'],
    ['url-decode', '%GG', 'Input is not valid URL-encoded text.'],
    ['url-decode', '%FF', 'Input is not valid URL-encoded text.'],
    ['url-decode', '%C3%28', 'Input is not valid URL-encoded text.'],
  ])('%s rejects malformed data %j and recovers', (selectedMode, input, error) => {
    render(<EncoderTool />); mode(selectedMode); edit(input);
    expect(screen.getByText(error)).toBeInTheDocument();
    expect(screen.getByText('Fix the input before using the output.')).toBeInTheDocument();
    expect(output()).toBeUndefined(); edit(selectedMode === 'base64-decode' ? 'SGVsbG8=' : 'Hello%20world');
    expect(output()).toBe(selectedMode === 'base64-decode' ? 'Hello' : 'Hello world');
  });

  it.each([
    ['base64-encode', 'Hello from IT Toolbox!', 'SGVsbG8gZnJvbSBJVCBUb29sYm94IQ=='],
    ['base64-decode', 'SGVsbG8gZnJvbSBJVCBUb29sYm94IQ==', 'Hello from IT Toolbox!'],
    ['url-encode', 'Hello from IT Toolbox!', 'Hello%20from%20IT%20Toolbox!'],
    ['url-decode', 'Hello%20from%20IT%20Toolbox%21', 'Hello from IT Toolbox!'],
  ])('restores the %s sample and output', (selectedMode, sample, expected) => {
    render(<EncoderTool />); edit('custom input'); mode(selectedMode);
    expect(screen.getByRole('textbox')).toHaveValue(sample); expect(output()).toBe(expected);
    fireEvent.focus(screen.getByRole('textbox')); expect(screen.getByRole('textbox')).toHaveValue(''); expect(output()).toBe('');
    fireEvent.blur(screen.getByRole('textbox')); expect(screen.getByRole('textbox')).toHaveValue(sample); expect(output()).toBe(expected);
  });
});
