import BN = require("bn.js");

const DRBG = require("bcrypto/lib/drbg");
const sha256 = require("bcrypto/lib/sha256");
const elliptic = require("elliptic");
const Signature = require("elliptic/lib/elliptic/ec/signature") as any;
const curve = elliptic.ec("secp256k1").curve;

export namespace schnorr {
  export const POOL64 = Buffer.allocUnsafe(64);
  export const alg = Buffer.from("Schnorr+SHA256  ", "ascii");

  export function trySign(msg: Buffer, prv: BN, k: BN, pn: Buffer): any {
    if (prv.isZero()) throw new Error("Bad private key.");
    if (prv.gte(curve.n)) throw new Error("Bad private key.");
    if (k.isZero()) return null;
    if (k.gte(curve.n)) return null;
    let r = curve.g.mul(k);
    if (pn) r = r.add(pn);
    if (r.y.isOdd()) {
      k = k.umod(curve.n);
      k = curve.n.sub(k);
    }
    const h = schnorr.hash(msg, r.getX());
    if (h.isZero()) return null;
    if (h.gte(curve.n)) return null;
    let s = h.imul(prv);
    s = k.isub(s);
    s = s.umod(curve.n);
    if (s.isZero()) return null;
    return new Signature({ r: r.getX(), s: s });
  }

  export function verify(msg: Buffer, signature: Buffer, key: Buffer): Buffer {
    const sig = new Signature(signature);
    const h = schnorr.hash(msg, sig.r);

    if (h.gte(curve.n)) throw new Error("Invalid hash.");

    if (h.isZero()) throw new Error("Invalid hash.");

    if (sig.s.gte(curve.n)) throw new Error("Invalid S value.");

    if (sig.r.gt(curve.p)) throw new Error("Invalid R value.");

    const k = curve.decodePoint(key);
    const l = k.mul(h);
    const r = curve.g.mul(sig.s);
    const rl = l.add(r);

    if (rl.y.isOdd()) throw new Error("Odd R value.");

    return rl.getX().eq(sig.r);
  }

  export function recover(signature: Buffer, msg: Buffer) {
    const sig = new Signature(signature);
    const h = schnorr.hash(msg, sig.r);

    if (h.gte(curve.n)) throw new Error("Invalid hash.");

    if (h.isZero()) throw new Error("Invalid hash.");

    if (sig.s.gte(curve.n)) throw new Error("Invalid S value.");

    if (sig.r.gt(curve.p)) throw new Error("Invalid R value.");

    let hinv = h.invm(curve.n);
    hinv = hinv.umod(curve.n);

    let s = sig.s;
    s = curve.n.sub(s);
    s = s.umod(curve.n);

    s = s.imul(hinv);
    s = s.umod(curve.n);

    const R = curve.pointFromX(sig.r, false);
    let l = R.mul(hinv);
    let r = curve.g.mul(s);
    const k = l.add(r);

    l = k.mul(h);
    r = curve.g.mul(sig.s);

    const rl = l.add(r);

    if (rl.y.isOdd()) throw new Error("Odd R value.");

    if (!rl.getX().eq(sig.r)) throw new Error("Could not recover pubkey.");

    return Buffer.from(k.encode("array", true));
  }

  export function combineSigs(sigs: Buffer[]): any {
    let s = new BN(0);
    let r, last;

    for (let i = 0; i < sigs.length; i++) {
      const sig = new Signature(sigs[i]);

      if (sig.s.isZero()) throw new Error("Bad S value.");

      if (sig.s.gte(curve.n)) throw new Error("Bad S value.");

      if (!r) r = sig.r;

      if (last && !last.r.eq(sig.r))
        throw new Error("Bad signature combination.");

      s = s.iadd(sig.s);
      s = s.umod(curve.n);

      last = sig;
    }

    if (s.isZero()) throw new Error("Bad combined signature.");

    return new Signature({ r: r, s: s });
  }

  export function combineKeys(keys: Buffer[]): Buffer {
    if (keys.length === 0) throw new Error();

    if (keys.length === 1) return keys[0];

    let point = curve.decodePoint(keys[0]);

    for (let i = 1; i < keys.length; i++) {
      const key = curve.decodePoint(keys[i]);
      point = point.add(key);
    }

    return Buffer.from(point.encode("array", true));
  }

  export function partialSign(
    msg: Buffer,
    priv: Buffer,
    privNonce: Buffer,
    pubNonce: Buffer
  ): any {
    const prv = new BN(priv);
    const k = new BN(privNonce);
    const pn = curve.decodePoint(pubNonce);
    const sig = schnorr.trySign(msg, prv, k, pn);

    if (!sig) throw new Error("Bad K value.");

    return sig;
  }

  export function generateNoncePair(
    msg: Buffer,
    priv: Buffer,
    data: Buffer
  ): Buffer {
    const drbg = schnorr.drbg(msg, priv, data);
    const len = curve.n.byteLength();

    let k = null;

    for (;;) {
      k = new BN(drbg.generate(len));

      if (k.isZero()) continue;

      if (k.gte(curve.n)) continue;

      break;
    }

    return Buffer.from(curve.g.mul(k).encode("array", true));
  }

  export function drbg(msg: Buffer, priv: Buffer, data: Buffer): any {
    const pers = Buffer.allocUnsafe(48);

    pers.fill(0);

    if (data) {
      console.assert(data.length === 32);
      data.copy(pers, 0);
    }

    schnorr.alg.copy(pers, 32);

    return new DRBG(sha256, priv, msg, pers);
  }

  export function hash(msg: Buffer, r: BN): BN {
    const R = r.toArrayLike(Buffer.from(""), "be", 32) as Buffer;
    const B = POOL64;

    R.copy(B, 0);
    msg.copy(B, 32);

    return new BN(sha256.digest(B));
  }

  export function sign(msg: Buffer, key: Buffer, nonce: Buffer): any {
    const prv = new BN(key);
    const drbg = schnorr.drbg(msg, key, nonce);
    const len = curve.n.byteLength();

    let pn;
    if (nonce) pn = curve.decodePoint(nonce);

    let sig;
    while (!sig) {
      const k = new BN(drbg.generate(len));
      sig = schnorr.trySign(msg, prv, k, pn);
    }

    return sig;
  }
}
