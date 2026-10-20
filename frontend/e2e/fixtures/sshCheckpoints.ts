// Public, fixed titles only. Never put inputs, key material or filenames here.
export const sshCheckpoints = [
  'SSH worker result', 'SSH clipboard comparison', 'SSH clipboard cleanup',
  'SSH download event', 'SSH download completion', 'SSH download file read', 'SSH download cleanup',
  'SSH binary file ready', 'SSH-1 protected round trip', 'SSH-1 plaintext round trip', 'SSH-1 cancellation',
] as const;
export type SshCheckpoint = typeof sshCheckpoints[number];
