import BN = require("bn.js");
import hashFunc = require("keccak");

export function hashOfBuffers(...buffers: Buffer[]): Buffer {
  const length = buffers.reduce(
    (len, buffer) => ((len += buffer.length), len),
    0
  );
  const final = Buffer.allocUnsafe(length);

  let offset = 0;
  buffers.forEach(buffer => {
    buffer.copy(final, offset);
    offset += buffer.length;
  });

  return Buffer.from(
    hashFunc("keccak" + 256)
      .update(final)
      .digest("hex"),
    "hex"
  );
}

Buffer.prototype.toInt = function(this: Buffer): BN {
  return new BN(this);
};
