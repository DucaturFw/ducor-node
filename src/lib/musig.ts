import BN = require("bn.js");
import utils from "./utils";

const DRBG = require("bcrypto/lib/drbg");
const sha256 = require("bcrypto/lib/sha256");
const elliptic = require("elliptic");
const Signature = require("elliptic/lib/elliptic/ec/signature") as any;
const curve = elliptic.ec("secp256k1").curve;

export type CombinedPublicKeys = Buffer;
export type GroupFactor = Buffer;
export default class musig {
  public static alg = Buffer.from("Schnorr+SHA256  ", "ascii");

  public static groupFactor(publicKeys: Buffer[]): GroupFactor {
    publicKeys.forEach(
      pub => console.assert(pub.length === publicKeys[0].length),
      "Not same length of pubkeys"
    );

    const pub_pool = Buffer.allocUnsafe(
      publicKeys[0].length * publicKeys.length
    );

    publicKeys.forEach((pub, index) => pub.copy(pub_pool, index * pub.length));
    return Buffer.from(sha256.digest(pub_pool), "hex");
  }

  public static groupPublicKey(
    publicKeys: Buffer[],
    factor?: GroupFactor
  ): Buffer {
    if (!factor) factor = musig.groupFactor(publicKeys);
    const publicPoints = publicKeys.map(pub => curve.decodePoint(pub));
    const memberHashes = publicKeys
      .map(pub => utils.hashOfBuffers(factor, pub))
      .map(hash => new BN(hash));

    return Buffer.from(
      Array(publicKeys.length)
        .fill(0)
        .reduce((point, index) => {
          if (!point) {
            return publicPoints[index].mul(memberHashes[index]);
          }

          return point.add(publicPoints[index].mul(memberHashes[index]));
        }, null)
        .encode()
    );
  }

  public static deterministinK(hash: Buffer, priv: Buffer, salt?: Buffer): any {
    const pers = Buffer.allocUnsafe(48);

    pers.fill(0);

    if (salt) {
      console.assert(salt.length === 32);
      salt.copy(pers, 0);
    }

    musig.alg.copy(pers, 32);

    return new DRBG(sha256, priv, hash, pers).generate(curve.n.byteLength());
  }

  public static personalRandomPoint(msg: Buffer, key: Buffer, salt?: Buffer) {
    const r = musig.deterministinK(msg, key, salt);
    return curve.g.mul(new BN(r)); //.encode("array", true);
  }

  public static groupRandomPoint(
    ...points: [string | Buffer | { x: BN; y: BN }][]
  ) {
    return points.reduce((point, current) => {
      let currentPoint;
      if (typeof current === "string") {
        currentPoint = curve.decodePoint(Buffer.from(current, "hex"));
      } else if (current instanceof Buffer) {
        currentPoint = curve.decodePoint(current);
      } else {
        currentPoint = current;
      }

      if (!point) {
        return currentPoint;
      }

      return (<any>point).add(currentPoint);
    }, null);
  }
}
