declare module 'bcrypt-pbkdf' {
  const bcrypt: { pbkdf(password: Uint8Array, passwordLength: number, salt: Uint8Array, saltLength: number, output: Uint8Array, length: number, rounds: number): number };
  export default bcrypt;
}
