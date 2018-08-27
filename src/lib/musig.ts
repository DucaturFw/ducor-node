import BN = require("bn.js");
import { hashOfBuffers } from "./utils";

import elliptic = require("elliptic");
const secp256k1 = elliptic.ec("secp256k1");
const Signature = require("elliptic/lib/elliptic/ec/signature");

type Point = typeof elliptic.Point;
type MUSignature = {
  r: Point;
  s: BN;
};

export function hashInt(...parts: (Buffer | BN | Point)[]): BN {
  return new BN(hash(...parts));
}

export function hash(...parts: (Buffer | BN | Point)[]): Buffer {
  return hashOfBuffers(
    ...parts.map(p => {
      if (p instanceof Buffer) {
        return p;
      }

      if (p instanceof BN) {
        return p.toBuffer();
      }

      if (p.x && p.y) {
        return Buffer.from(p.encode(16));
      }

      throw new Error("unknown type of part: " + typeof p);
    })
  );
}

export function L(Pn: Point[]): BN {
  return hashInt(...Pn);
}

export function getAggregatePublicKey(L: BN, Xs: Point[]): Point {
  let X = Xs[0].mul(hashInt(L, Xs[0]));

  for (let i = 1; i < Xs.length; i++) {
    X = X.add(Xs[i].mul(hashInt(L, Xs[i])));
  }

  return X;
}

export function R(Pn: Point[]): Point {
  let R = Pn[0];

  for (let i = 1; i < Pn.length; i++) {
    R = R.add(Pn[i]);
  }

  return R;
}

export function getSi(
  ri: BN,
  X: Point,
  R: Point,
  m: Buffer,
  L: BN,
  xi: BN,
  Xi: Point
): MUSignature {
  var s = hashInt(R, X, m)
    .mul(hashInt(L, Xi))
    .mul(xi);
  var si = ri.add(s).umod(secp256k1.curve.n);
  return {
    r: R,
    s: si
  };
}

export function combine(sigs: MUSignature[], R: Point): MUSignature {
  let S = sigs[0].s;

  for (let i = 1; i < sigs.length; i++) {
    S = S.add(sigs[i].s);
  }

  return {
    r: R,
    s: S
  };
}

export function verify(m: Buffer, s: MUSignature, X: Point, R: Point): boolean {
  const lPoint = secp256k1.curve.g.mul(s.s);
  const rPoint = R.add(X.mul(hashInt(R, X, m)));

  return lPoint.eq(rPoint);
}
