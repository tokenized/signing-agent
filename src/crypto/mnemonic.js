import { Buffer } from 'buffer';

export async function mnemonic2Seed(mnemonic, passphrase = '') {
  if (typeof passphrase !== 'string') {
    throw new TypeError('passphrase must be a string or undefined');
  }
  mnemonic = mnemonic.normalize('NFKD');
  passphrase = passphrase.normalize('NFKD');
  const mbuf = Buffer.from(mnemonic);
  const pbuf = Buffer.concat([
    Buffer.from('mnemonic'),
    Buffer.from(passphrase),
  ]);


  const key = await crypto.subtle.importKey(
    'raw',
    mbuf,
    { name: 'PBKDF2' },
    false,
    ['deriveBits'],
  );
  const seedValue = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: pbuf,
      iterations: 2048,
      hash: {
        name: 'SHA-512',
      },
    },
    key,
    64 << 3,
  );
  return Buffer.from(seedValue);
}

export function normalizeMnemonic(enteredString) {
  return enteredString
      ? enteredString
          .normalize('NFKD')
          .toLowerCase()
          .split(/\s+/)
          .filter(Boolean)
          .join(' ')
      : '';
}

