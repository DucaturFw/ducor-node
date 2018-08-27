import BN = require("bn.js");

const sha256 = require("bcrypto/lib/sha256");

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

  return Buffer.from(sha256.digest(final), "hex");
}

Buffer.prototype.toInt = function(this: Buffer): BN {
  return new BN(this);
};
