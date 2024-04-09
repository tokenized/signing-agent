import { Buffer } from 'buffer';
import ReadBuffer from './ReadBuffer.js';
import WriteBuffer from './WriteBuffer.js';
import Hash from './Hash.js';

// Input is a Bitcoin input containing the hash and index of the UTXO being spent as well as a
//   unlocking script and sequence value.
export default class Input {
  constructor(serialized) {
    this.hash = null;
    this.index = 0;
    this.script = new ArrayBuffer();
    this.sequence = 0xffffffff;

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
          `Must provide a string or buffer to deserialize an Input: ${typeof serialized}`,
        );
      }
    }
  }

  // fromString reads a hex string containing a serialized input.
  fromString(string) {
    this.fromReadBuffer(new ReadBuffer(string));
  }

  // fromReadBuffer reads a serialized input from a ReadBuffer.
  fromReadBuffer(buf) {
    this.hash = new Hash(buf.read(32));
    this.index = buf.readUInt32LE();

    const sizeScript = buf.readVarIntNum();
    this.script = buf.read(sizeScript);

    this.sequence = buf.readUInt32LE();

    return this;
  }

  // toBytes returns a Buffer containing the input serialized in binary format.
  toBytes() {
    const writeBuffer = new WriteBuffer();
    this.write(writeBuffer);
    return writeBuffer.toBytes();
  }

  // write writes the input into a WriteBuffer in binary format.
  write(writeBuffer) {
    writeBuffer.write(this.hash.toBytes());
    writeBuffer.writeUInt32LE(this.index);

    writeBuffer.writeVarIntNum(this.script.byteLength);
    writeBuffer.write(this.script);

    writeBuffer.writeUInt32LE(this.sequence);
  }
}
