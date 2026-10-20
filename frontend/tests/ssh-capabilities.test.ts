// @vitest-environment node
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { Request, Result } from '../src/tools/ssh-key-generator/sshTypes';

const endpoint = { onmessage: null as ((event: MessageEvent) => Promise<void>) | null, postMessage: vi.fn() };
const options = { protected: false, passphrase: '', confirmation: '', unencryptedAcknowledged: true, formats: ['public'] as const };
function request(algorithm: string, legacyAcknowledged = false): Request {
  return { operation: 'generate', algorithm, legacyAcknowledged, comment: '', options: { ...options, formats: [...options.formats] } };
}
async function send(data: Request | { operation: 'capabilities' }) {
  endpoint.postMessage.mockClear();
  await endpoint.onmessage!(new MessageEvent('message', { data }));
  expect(endpoint.postMessage).toHaveBeenCalledOnce();
  return endpoint.postMessage.mock.calls[0][0] as { supported?: string[]; result?: Result; error?: string };
}
function provider(rejectedSizes: number[], rejectOtherAlgorithms = false) {
  const native = crypto.subtle.generateKey.bind(crypto.subtle);
  return vi.spyOn(crypto.subtle, 'generateKey').mockImplementation(async (params, extractable, usages) => {
    const rsa = typeof params === 'object' && 'modulusLength' in params;
    if (rsa ? rejectedSizes.includes((params as RsaHashedKeyGenParams).modulusLength) : rejectOtherAlgorithms) {
      throw new Error('provider detail that must not be published');
    }
    return native(params, extractable, usages);
  });
}
beforeEach(async () => {
  vi.resetModules();
  vi.stubGlobal('self', endpoint);
  await import('../src/tools/ssh-key-generator/ssh.worker');
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

test('mount capabilities do not generate any RSA keys, even on an RSA-only provider', async () => {
  const generate = provider([1024], true);
  expect((await send({ operation: 'capabilities' })).supported).toEqual(['rsa-lazy', 'dsa-lazy', 'ed448']);
  expect(generate).toHaveBeenCalledTimes(4);
  expect(generate.mock.calls.every(([params]) => typeof params !== 'object' || !('modulusLength' in params))).toBe(true);
});

for (const bits of [2048, 3072, 4096]) test(`RSA ${bits} succeeds independently of rejected RSA 1024`, async () => {
  const generate = provider([1024]);
  const response = await send(request(`rsa${bits}`));
  expect(response.error).toBeUndefined();
  expect(response.result?.inspector.parameters).toBe(`${bits} bits; exponent 65537`);
  expect(response.result?.outputs.map(output => output.format)).toEqual(['public']);
  expect(generate).toHaveBeenCalledOnce();
  expect(generate.mock.calls[0][0]).toMatchObject({ modulusLength: bits });
}, 30_000);

test('legacy acknowledgment is required before the provider is called; acknowledged rejection has no fallback', async () => {
  const generate = provider([1024]);
  const guarded = await send(request('rsa1024'));
  expect(guarded.result).toBeUndefined();
  expect(guarded.error).toContain('Legacy generation requires');
  expect(generate).not.toHaveBeenCalled();
  const rejected = await send(request('rsa1024', true));
  expect(rejected.result).toBeUndefined();
  expect(rejected.error).toContain('Unsupported native generation of RSA 1024-bit');
  expect(rejected.error).not.toContain('provider detail');
  expect(generate).toHaveBeenCalledOnce();
  expect(generate.mock.calls[0][0]).toMatchObject({ modulusLength: 1024 });
});

test('an unsupported modern size fails without output or substitution; another size can still succeed', async () => {
  const generate = provider([1024, 3072]);
  const rejected = await send(request('rsa3072'));
  expect(rejected.result).toBeUndefined();
  expect(rejected.error).toContain('Unsupported native generation of RSA 3072-bit');
  expect(rejected.error).toContain('no other key size or algorithm was attempted');
  expect(rejected.error).not.toContain('provider detail');
  expect(generate).toHaveBeenCalledOnce();
  expect(generate.mock.calls[0][0]).toMatchObject({ modulusLength: 3072 });
  const recovered = await send(request('rsa2048'));
  expect(recovered.error).toBeUndefined();
  expect(recovered.result?.inspector.parameters).toBe('2048 bits; exponent 65537');
  expect(generate).toHaveBeenCalledTimes(2);
  expect(generate.mock.calls[1][0]).toMatchObject({ modulusLength: 2048 });
});

test('RSA 8192 requests exactly 8192/65537 once, sanitizes provider failure and recovers without fallback', async () => {
  const generate = provider([8192]);
  const rejected = await send(request('rsa8192'));
  expect(rejected.result).toBeUndefined();
  expect(rejected.error).toContain('Unsupported native generation of RSA 8192-bit');
  expect(rejected.error).toContain('no other key size or algorithm was attempted');
  expect(rejected.error).not.toContain('provider detail');
  expect(generate).toHaveBeenCalledOnce();
  expect(generate.mock.calls[0]).toEqual([
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 8192, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify'],
  ]);
  const recovered = await send(request('rsa2048'));
  expect(recovered.error).toBeUndefined();
  expect(recovered.result?.inspector.parameters).toBe('2048 bits; exponent 65537');
  expect(generate).toHaveBeenCalledTimes(2);
});

test('missing required worker primitives do not advertise lazy RSA availability', async () => {
  vi.stubGlobal('WebAssembly', undefined);
  expect((await send({ operation: 'capabilities' })).supported).toEqual([]);
});

test('Ed448 worker rejects stale OpenSSH export requests before generation and after PPK import', async () => {
  const stale = request('ed448'); stale.options.formats = ['public', 'openssh', 'ppk'];
  const generate = vi.spyOn(crypto, 'getRandomValues');
  const rejected = await send(stale);
  expect(rejected.error).toContain('Unsupported openssh format for ed448'); expect(rejected.result).toBeUndefined();
  expect(generate).not.toHaveBeenCalled();
  const plain = request('ed448'); plain.options.formats = ['public', 'ppk'];
  const generated = await send(plain);
  expect(generated.result?.outputs.map(item => item.format)).toEqual(['public', 'ppk']);
  const converted = await send({ operation: 'convert', text: generated.result!.outputs[1].text, passphrase: '', options: stale.options });
  expect(converted.error).toContain('Unsupported openssh'); expect(converted.result).toBeUndefined();
});

test('Ed448 secure-random failure has no output or algorithm fallback, then recovers', async () => {
  const nativeGenerate = vi.spyOn(crypto.subtle, 'generateKey');
  const random = vi.spyOn(crypto, 'getRandomValues').mockImplementationOnce(() => { throw new Error('sensitive provider failure'); });
  const failed = await send(request('ed448'));
  expect(failed.result).toBeUndefined(); expect(failed.error).toContain('No output was produced');
  expect(failed.error).not.toContain('sensitive provider failure');
  expect(random).toHaveBeenCalledOnce(); expect(nativeGenerate).not.toHaveBeenCalled();
  const recovered = await send(request('ed448'));
  expect(recovered.error).toBeUndefined(); expect(recovered.result?.inspector.identifier).toBe('ssh-ed448');
  expect(nativeGenerate).not.toHaveBeenCalled();
});
for (const id of ['rsa512', 'rsa768']) test(`${id}: exact native attempt, legacy gate, rejection and no size/library fallback`, async () => {
  const bits = Number(id.slice(3)), generate = provider([bits]);
  expect((await send(request(id))).error).toContain('Legacy generation'); expect(generate).not.toHaveBeenCalled();
  const rejected = await send(request(id, true));
  expect(rejected.result).toBeUndefined(); expect(rejected.error).toContain(`Unsupported native generation of RSA ${bits}-bit`);
  expect(generate).toHaveBeenCalledOnce(); expect(generate.mock.calls[0][0]).toMatchObject({ modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]) });
  expect((await send(request('rsa2048'))).result).toBeDefined();
});
test('DSA secure-random failure is sanitized, never calls native generation and does not fall back', async () => {
  const generate = vi.spyOn(crypto.subtle, 'generateKey'), rng = vi.spyOn(crypto, 'getRandomValues').mockImplementationOnce(() => { throw new Error('private provider detail'); });
  const rejected = await send(request('dsa', true));
  expect(rejected.result).toBeUndefined(); expect(rejected.error).toContain('No output was produced'); expect(rejected.error).not.toContain('private provider detail');
  expect(rng).toHaveBeenCalledOnce(); expect(generate).not.toHaveBeenCalled();
  const recovered = await send(request('ed448')); expect(recovered.result).toBeDefined();
});
for (const id of ['rsa512', 'rsa768']) test(`${id}: provider returning another modulus size produces no output`, async () => {
  const native = crypto.subtle.generateKey.bind(crypto.subtle);
  const generate = vi.spyOn(crypto.subtle, 'generateKey').mockImplementation(async () => native({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']));
  const rejected = await send(request(id, true));
  expect(rejected.result).toBeUndefined(); expect(rejected.error).toContain('Key consistency validation failed'); expect(generate).toHaveBeenCalledOnce();
  expect(generate.mock.calls[0][0]).toMatchObject({ modulusLength: Number(id.slice(3)) });
});
