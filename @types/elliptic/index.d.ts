declare module "elliptic" {
  class RedBN {
    redAdd(b: RedBN): RedBN;
    redIAdd(b: RedBN): RedBN;
    redSub(b: RedBN): RedBN;
    redISub(b: RedBN): RedBN;
    redShl(num: number): RedBN;
    redMul(b: RedBN): RedBN;
    redIMul(b: RedBN): RedBN;
    redSqr(): RedBN;
    redISqr(): RedBN;
    /**
     * @description square root modulo reduction context's prime
     */
    redSqrt(): RedBN;
    /**
     * @description  modular inverse of the number
     */
    redInvm(): RedBN;
    redNeg(): RedBN;
    /**
     * @description modular exponentiation
     */
    redPow(b: RedBN): RedBN;
    fromRed(): BN;
  }

  type BN = import("bn.js");
  type Hash = Uint8Array | Buffer | number[] | ArrayLike<number>;
  type Key = Hash | BN;
  type Encs = 8 | 10 | 16;
  type ToHex = "hex";

  type CurvePreset =
    | "p192"
    | "p224"
    | "p256"
    | "p384"
    | "p521"
    | "curve25519"
    | "ed25519"
    | "secp256k1";

  interface ICurveConfiguration {
    type: string;
    prime: any | null;
    p: string;
    a: string;
    b: string;
    n: string;
    hash: any;
    gRed: boolean;
    g: string[];
  }

  type CurveType = "short" | "mont" | "edwards";

  interface KeyPairOptions {
    priv?: BN;
    pub?: Point;
  }

  class ECSignature {
    r: BN;
    s: BN;
    recoveryParam: any;

    new(other: ECSignature): ECSignature;
    new();

    _importDER(data, enc): any;
    toDER(enc): string | ArrayLike<number>;
  }

  class KeyPair implements KeyPairOptions {
    ec: EC;
    priv: BN | null;
    pub: Point | null;

    static fromPublic(ec: EC, pub: Key, enc?: Encs);
    static fromPrivate(ec: EC, priv: Key, enc?: Encs);

    private _importPrivate(key, enc): any;
    private _importPublic(key, enc): any;

    validate(): { result: boolean; reason: string };

    getPublic(compact: boolean, enc?: Encs): Point;
    getPublic(enc?: Encs): Point;

    getPrivate(enc?: Encs): BN;

    derive(pub: Key): BN;

    sign(
      msg: Hash,
      enc?: Encs,
      options?: { pers: any; persEnc?: Encs }
    ): ECSignature;

    sign(msg: Hash, options: { pers: any; persEnc?: Encs }): ECSignature;

    verify(msg: Hash, signature: ECSignature): boolean;

    inspect(): string;
  }

  type PointCoordinate = BN; // & { red: boolean; fromRed: () => BN };

  class Point {
    x: PointCoordinate;
    y: PointCoordinate;

    red: boolean;

    encodeCompressed(enc?: Encs): number[];
    encodeCompressed(enc: ToHex): string;
    encode(enc?: Encs, compact?: boolean): number[];
    encode(enc: ToHex, compact?: boolean): string;

    // TODO: understand it please
    precompute(power: any): any;

    validate(): any;
    dblp(k: number): Point;
    inspect(): string;
    isInfinity(): boolean;
    dbl(): Point;

    add(p: Point): Point;
    mul(k: BN): Point;
    mulAdd(k1, p, k2): Point;
    jmulAdd(k1, p, k2): Point;
    normalize(): Point;
    neg(): Point;
    getX(): BN;
    getY(): BN;
    eq(other: Point): boolean;
    eqXToP(x): boolean;
    precompute(): Point;
    inspect(): string;
    isInfinity(): boolean;
    diffAdd(p, diff): Point;
    jumlAdd(): Point;
    toJSON(): string;
    toJ(): JPoint;
    toP(): Point;
  }

  interface JPoint extends Point {
    mixedAdd(p: Point | JPoint): JPoint;
    trpl(): JPoint;
  }

  interface BaseCurve {
    type: CurveType;
    p: BN;

    // Use Montgomery, when there is no fast reduction for the prime
    red: RedBN;

    // Useful for many curves
    zero: RedBN;
    one: RedBN;
    two: RedBN;

    // Curve configuration, optional
    n: BN;
    g: Point;

    // Temporary arrays
    redN: RedBN;

    decodePoint(bytes: Key, enc?: Encs): Point;
  }

  interface Curve extends BaseCurve {
    a: BN;
    b: BN;
    tinv: RedBN;
    endo: {
      beta: RedBN;
      lambda: BN;
      basis: BN;
    };

    pointFromX(x, odd): Point;
    validate(point): any;
    point(x, y, isRed): Point;
    pointFromJSON(obj: any, red?: any): Point;
    jpoint(x, y, z): any;
  }

  interface EC {
    curve: Curve;
    n: BN;
    nh: BN;
    g: Point;
    hash: Hash;

    keyPair(options): KeyPair;
    keyFromPrivate(priv, enc): KeyPair;
    keyFromPublic(pub, enc): KeyPair;
    genKeyPair(options): KeyPair;
    _truncateToN(msg, truncOnly): any;
    sign(msg, key, enc, options): any;
    verify(msg: Buffer, signature: { r: Point; s: BN }, key: Point): boolean;
    recoverPubKey(msg, signature, j, enc): any;
    getKeyRecoveryParam(e, signature, Q, enc): any;
  }

  interface IEllipticModule {
    version: number;
    rand: typeof import("brorand");
    utils: any;

    curve: {
      base: any;
      short: any;
      mont: any;
      edwards: any;
    };

    curves: {
      PresetCurve: new (config: ICurveConfiguration) => EC;
    };

    ec(other: EC): EC;
    ec(shortcur: CurvePreset): EC;
    ec(preset: new (...args: any[]) => EC): EC;

    eddsa: any;

    Point: Point;
    EC: EC;
  }

  const elliptic: IEllipticModule;
  export = elliptic;
}
