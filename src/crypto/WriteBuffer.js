// WriteBuffer creates a Buffer from a series of sequential writes.
export default class WriteBuffer {
  constructor() {
    this.bufs = [];
    this.length = 0;
  }

  // write writes the contents of a buffer.
  write(buf) {
    if (!(buf?.constructor?.name === 'ArrayBuffer')) {
      if (buf.buffer) {
        buf = buf.buffer;
      } else {
        throw new Error('write non buffer to WriteBuffer');
      }
    }
    if (buf.byteLength == 0) {
      return;
    }
    this.bufs.push(buf);
    this.length += buf.byteLength;
  }

  // writeUInt8 writes a 8 bit unsigned integer.
  writeUInt8(value) {
    const buf = new Uint8Array([value]);
    this.bufs.push(buf.buffer);
    this.length += 1;
  }

  // writeUInt16LE writes a 16 bit unsigned integer in little endian format.
  writeUInt16LE(value) {
    const buf = new ArrayBuffer(2);
    const view = new DataView(buf);
    view.setUint16(0, value, true);
    this.bufs.push(buf);
    this.length += 2;
  }

  // writeUInt32LE writes a 32 bit unsigned integer in little endian format.
  writeUInt32LE(value) {
    const buf = new ArrayBuffer(4);
    const view = new DataView(buf);
    view.setUint32(0, value, true);
    this.bufs.push(buf);
    this.length += 4;
  }

  // writeUInt32BE writes a 32 bit unsigned integer in big endian format.
  writeUInt32BE(value) {
    const buf = new ArrayBuffer(4);
    const view = new DataView(buf);
    view.setUint32(0, value, false);
    this.bufs.push(buf);
    this.length += 4;
  }

  // writeInt32LE writes a 32 bit signed integer in little endian format.
  writeInt32LE(value) {
    const buf = new ArrayBuffer(4);
    const view = new DataView(buf);
    view.setInt32(0, value, true);
    this.bufs.push(buf);
    this.length += 4;
  }

  // writeVarIntNum writes a Bitcoin P2P encoding variable sized integer.
  writeVarIntNum(value) {
    if (value?.constructor?.name === 'ArrayBuffer') {
      if (value.byteLength == 8) {
        const buf32 = new Uint32Array(value.buffer);
        if (buf32[1] != 0) {
          const bytes = Uint8Array(9);
          bytes[0] = 0xff;
          bytes.set(buf32, 1); // copy both 32 bit values into buffer
          this.bufs.push(bytes.buffer);
          this.length += 9;
        }
      } else {
        throw new Error(
          `WriteBuffer var int from array size not 8: ${value.byteLength}`,
        );
      }
    } else if (value < 0xfd) {
      const bytes = new Uint8Array([value]);
      this.bufs.push(bytes.buffer);
      this.length += 1;
    } else if (value <= 0xffff) {
      const buf = new ArrayBuffer(3);
      const view = new DataView(buf);
      view.setUint8(0, 0xfd);
      view.setUint16(1, value, true);
      this.bufs.push(buf);
      this.length += 3;
    } else if (value <= 0xffffffff) {
      const buf = new ArrayBuffer(5);
      const view = new DataView(buf);
      view.setUint8(0, 0xfe);
      view.setUint32(1, value, true);
      this.bufs.push(buf);
      this.length += 5;
    } else {
      throw new Error('WriteBuffer Var Int over 32 bits');
    }
  }

  // writePushData writes a Bitcoin script push data. It precedes the data with a variable size.
  writePushData(data) {
    if (!(data?.constructor?.name === 'ArrayBuffer')) {
      throw new Error('WriteBuffer.writePushData non array buffer');
    }

    if (data.byteLength <= 0x4b) {
      // Max single byte push data size
      this.writeUInt8(data.byteLength);
    } else if (data.byteLength <= 0xff) {
      this.writeUInt8(0x4c); // OP_PUSH_DATA_1
      this.writeUInt8(data.byteLength);
    } else if (data.byteLength <= 0xffff) {
      this.writeUInt8(0x4d); // OP_PUSH_DATA_2
      this.writeUInt16LE(data.byteLength);
    } else if (data.byteLength <= 0xffffffff) {
      this.writeUInt8(0x4e); // OP_PUSH_DATA_4
      this.writeUInt32LE(data.byteLength);
    } else {
      throw new Error('WriteBuffer.writePushData data write size over 32 bits');
    }

    this.write(data);
  }

  // toBytes returns a single ArrayBuffer containing all of the data written.
  toBytes() {
    var result = new Uint8Array(this.length);
    var offset = 0;
    this.bufs.forEach((buf) => {
      const bytes = new Uint8Array(buf);
      result.set(bytes, offset);
      offset += buf.byteLength;
    });
    return result.buffer;
  }
}
