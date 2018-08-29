import BN = require("bn.js");
import { soliditySHA3 } from "ethereumjs-abi";
import keccak = require("keccak");
import elliptic = require("elliptic");
// const secp256k1 = elliptic.ec("secp256k1");

export const ecurve = elliptic.ec(
  new elliptic.curves.PresetCurve({
    type: "short",
    prime: null,
    p: "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
    a: "0",
    b: "3",
    n: "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
    hash: require("hash.js").sha256,
    gRed: false,
    g: ["1", "2"]
  })
) as any;

type Point = typeof elliptic.Point;
type MUSignature = {
  r: Point;
  s: BN;
};

export function hashPublicKeys(keys: Point[]): BN {
  const coords = keys.map(p => [p.x, p.y]);
  const data = coords.reduce((acc, coord) => acc.concat(coord), []);
  return new BN(soliditySHA3(Array(keys.length * 2).fill("uint256"), data));
}

export function hashNonceWithKey(nonce: BN, groupKey: Point): BN {
  return new BN(
    soliditySHA3(
      ["uint256", "uint256", "uint256"],
      [nonce, groupKey.x, groupKey.y]
    )
  );
}

export function hashGroupKeyWithPointAndMessage(
  randomPoint: Point,
  groupKey: Point,
  message: Buffer
): BN {
  return new BN(
    soliditySHA3(
      ["uint256", "uint256", "uint256", "uint256", "bytes32"],
      [groupKey.x, groupKey.y, randomPoint.x, randomPoint.y, message]
    )
  );
}

export function hash(b: Buffer): Buffer {
  return Buffer.from(
    keccak("keccak" + 256)
      .update(b)
      .digest("hex"),
    "hex"
  );
}

export function signerGroupNonce(Pn: Point[]): BN {
  return hashPublicKeys(Pn);
}

export function getAggregatePublicKey(nonce: BN, publicKeys: Point[]): Point {
  let aggregated = publicKeys[0].mul(hashNonceWithKey(nonce, publicKeys[0]));

  for (let i = 1; i < publicKeys.length; i++) {
    aggregated = aggregated.add(
      publicKeys[i].mul(hashNonceWithKey(nonce, publicKeys[i]))
    );
  }

  return aggregated;
}

export function aggregatedPoint(randomPoints: Point[]): Point {
  let aggregated = randomPoints[0];

  for (let i = 1; i < randomPoints.length; i++) {
    aggregated = aggregated.add(randomPoints[i]);
  }

  return aggregated;
}

export function getSignature(
  randomNumber: BN,
  groupPublicKey: Point,
  randomPoint: Point,
  message: Buffer,
  groupNonce: BN,
  personalPrivateKey: BN,
  personalPublicKey: Point
): MUSignature {
  var s = hashGroupKeyWithPointAndMessage(randomPoint, groupPublicKey, message)
    .mul(hashNonceWithKey(groupNonce, personalPublicKey))
    .mul(personalPrivateKey);
  var si = randomNumber.add(s).umod(ecurve.curve.n);
  return {
    r: randomPoint,
    s: si
  };
}

export function combineSignatures(
  signaturess: MUSignature[],
  randomPoint: Point
): MUSignature {
  let signature = signaturess[0].s;

  for (let i = 1; i < signaturess.length; i++) {
    signature = signature.add(signaturess[i].s);
  }

  return {
    r: randomPoint,
    s: signature
  };
}

export function verifySignature(
  message: Buffer,
  signature: MUSignature,
  groupPublicKey: Point,
  groupRandomPoint: Point
): boolean {
  const lPoint = ecurve.curve.g.mul(signature.s);
  const rPoint = groupRandomPoint.add(
    groupPublicKey.mul(
      hashGroupKeyWithPointAndMessage(groupRandomPoint, groupPublicKey, message)
    )
  );

  return lPoint.eq(rPoint);
}
