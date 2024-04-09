import { Buffer } from 'buffer';
import ReadBuffer from './ReadBuffer.js';
import WriteBuffer from './WriteBuffer.js';
import { bytesToNumber, numberToBytes, padBytesEnd } from './utils.js';

// Output is a Bitcoin output containing a value and a locking script.
export default class Output {
  constructor(serialized) {
    // bigint literals break JSDoc. So sorry.
    this.value = BigInt(0);
    this.script = new ArrayBuffer();

    if (serialized) {
      if (typeof serialized === 'string' || serialized instanceof String) {
        this.fromString(serialized);
      } else if (serialized instanceof ReadBuffer) {
        this.fromReadBuffer(serialized);
      } else if (Buffer.isBuffer(serialized)) {
        this.fromReadBuffer(new ReadBuffer(serialized));
      } else if (serialized?.constructor?.name === 'ArrayBuffer') {
        this.fromReadBuffer(new ReadBuffer(serialized));
      } else {
        throw new TypeError(
          `Must provide a string or buffer to deserialize an Output: ${typeof serialized}`,
        );
      }
    }
  }

  // fromString reads a hex string containing a serialized output.
  fromString(string) {
    this.fromReadBuffer(new ReadBuffer(string));
  }

  // fromReadBuffer reads a serialized output from a ReadBuffer.
  fromReadBuffer(buf) {
    const b = new Uint8Array(buf.read(8));
    b.reverse();
    this.value = bytesToNumber(b);

    const sizeScript = buf.readVarIntNum();
    this.script = buf.read(sizeScript);

    return this;
  }

  // toBytes returns a Buffer containing the output serialized in binary format.
  toBytes() {
    const writeBuffer = new WriteBuffer();
    this.write(writeBuffer);
    return writeBuffer.toBytes();
  }

  // write writes the output into a WriteBuffer in binary format.
  write(writeBuffer) {
    this.normalizeValue();

    const b = numberToBytes(this.value);
    b.reverse();
    const valueBytes = padBytesEnd(b, 8);
    writeBuffer.write(valueBytes);

    writeBuffer.writeVarIntNum(this.script.byteLength);
    writeBuffer.write(this.script);
  }

  normalizeValue() {
    if (typeof this.value === 'number') {
      this.value = BigInt(this.value);
      return;
    }
  }
}
