export async function encrypt(input, keyData) {
  const iv = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    'jwk',
    keyData,
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  );

  const encBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    input,
  );

  const aesBuffer = Buffer.concat([
    Buffer.from(iv.buffer),
    Buffer.from(encBuffer),
  ]);

  // HMAC has been removed from the algorithm as the AES-GCM is already authenticated

  return aesBuffer;
}

export async function decrypt(encrypted, keyData) {
  if (encrypted.length < (256 + 128 + 128) / 8) {
    throw new Error(
      `Invalid data length ${encrypted.length} (should be at least 256+128+128 bits)`,
    );
  }

  const iv = encrypted.slice(0, 128 / 8);

  const encBuffer = encrypted.slice(128 / 8);

  const key = await crypto.subtle.importKey(
    'jwk',
    keyData,
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  );

  return await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    encBuffer,
  );
}

async function deriveKey(password) {
  return await crypto.subtle.digest('SHA-256', Buffer.from(password));
}

export async function decryptWithPassword(encrypted, password) {
  return await decrypt(encrypted, await deriveKey(password));
}

export async function encryptWithPassword(input, password) {
  return await encrypt(input, await deriveKey(password));
}


export async function createSecretJWK() {
  return await crypto.subtle.exportKey(
      'jwk',
      await crypto.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          true,
          ['decrypt', 'encrypt']
      ),
  );
}

export async function createSecretKeyBytes() {
  return await crypto.subtle.exportKey(
      'raw',
      await crypto.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          true,
          ['decrypt', 'encrypt']
      ),
  );
}

