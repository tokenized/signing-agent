import { secp256k1 } from '@noble/curves/secp256k1';
// import isValid from 'bitcoin-address-validation';

// export function isBsvAddress(input) {
//   return !!isValid(input);
// }

export function arrayBufferToHex(array) {
  const bytes = new Uint8Array(array);
  return Array.from(bytes, (byte) =>
    ('0' + (byte & 0xff).toString(16)).slice(-2),
  ).join('');
}

function hexValue(h) {
  const cc = h.charCodeAt(0);
  if (cc <= 0x39) {
    // '9'
    return cc - 0x30; // '0'
  }
  if (cc <= 0x46) {
    // 'F'
    return cc - 0x41 + 10; // 'A'
  }
  return cc - 0x61 + 10; // 'a'
}

export function hexToArrayBuffer(hexString) {
  var result = new Uint8Array(hexString.length / 2);

  for (var i = 0, j = 0; i < hexString.length; i += 2, j += 1) {
    result[j] = hexValue(hexString[i]) * 16 + hexValue(hexString[i + 1]);
  }

  return result.buffer;
}

export function arrayBuffersAreEqual(buf1, buf2) {
  if (buf1.byteLength !== buf2.byteLength) {
    return false;
  }

  const bytes1 = new Uint8Array(buf1);
  const bytes2 = new Uint8Array(buf2);
  for (let i = 0; i < buf1.byteLength; i += 1) {
    if (bytes1[i] !== bytes2[i]) {
      return false;
    }
  }

  return true;
}

function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i += 1) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function hexToBytes(hex) {
  hex = hex.length & 1 ? `0${hex}` : hex;
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i += 1) {
    let j = i * 2;
    array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
  }
  return array;
}

function hexToNumber(hex) {
  if (typeof hex !== 'string') {
    throw TypeError(`hexToNumber: expected string, got ${typeof hex}`);
  }
  return BigInt(`0x${hex}`);
}

export function bytesToNumber(bytes) {
  return hexToNumber(bytesToHex(bytes));
}

function numberToHex(num) {
  if (!(typeof num !== 'bigint')) {
    num = BigInt(num);
  }
  const hex = num.toString(16);
  return hex.length & 1 ? `0${hex}` : hex;
}

export function numberToBytes(n) {
  return hexToBytes(numberToHex(n));
}

export function padBytes(bytes, size) {
  if (bytes.byteLength >= size) {
    return bytes;
  }

  const result = new Uint8Array(size);
  result.set(bytes, size - bytes.byteLength);
  return result;
}

export function padBytesEnd(bytes, size) {
  if (bytes.byteLength >= size) {
    return bytes;
  }

  const result = new Uint8Array(size).fill(0);
  result.set(bytes);
  return result;
}

export function mod(a, b = secp256k1.CURVE.P) {
  const result = a % b;
  return result >= 0 ? result : b + result;
}

function egcd(a, b) {
  let [x, y, u, v] = [BigInt(0), BigInt(1), BigInt(1), BigInt(0)];
  while (a !== 0n) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    [b, a] = [a, r];
    [x, y] = [u, v];
    [u, v] = [m, n];
  }
  const gcd = b;
  return [gcd, x, y];
}

export function invert(number, modulo = secp256k1.CURVE.P) {
  if (number === 0n || modulo <= 0n) {
    throw new Error('invert: expected positive integers');
  }
  const [gcd, x] = egcd(mod(number, modulo), modulo);
  if (gcd !== 1n) {
    throw new Error('invert: does not exist');
  }
  return mod(x, modulo);
}
