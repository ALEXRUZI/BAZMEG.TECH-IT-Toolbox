export function normalizeFixtureRequest(payload: unknown): { query: { queryName: string } };
export function createTxtContractFixture(payload: unknown): Promise<unknown>;
export function createDnsContractFixtures(): Promise<Record<'success' | 'nxdomain' | 'incomplete' | 'formerr' | 'notimp' | 'timeout' | 'resolverError' | 'burst', unknown>>;
