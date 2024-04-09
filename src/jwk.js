export async function importPrivateKey(privateJWK) {
    return await crypto.subtle.importKey(
    'jwk',
    privateJWK,
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign'],
  );
}

export async function generateECDSAJWK() {
  const keys = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify'],
  );

  const privateJWK = await crypto.subtle.exportKey('jwk', keys.privateKey);

  const publicJWK = await crypto.subtle.exportKey('jwk', keys.publicKey);

  const keyId = Buffer.from(
    await crypto.subtle.digest(
      'SHA-256',
      await crypto.subtle.exportKey('raw', keys.publicKey),
    ),
  ).toString('hex');

  return { keyId, privateJWK, publicJWK };
}
