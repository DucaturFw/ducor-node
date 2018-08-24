import musig from "../lib/musig";
import "jest-extended";
const { secp256k1, hash256 } = require("bcrypto");
const elliptic = require("elliptic");
const curve = elliptic.ec("secp256k1").curve;

describe("musig cryptography tests", () => {
  const keys = [
    "5163d545d17016acac014f8ffee3f0a11ace3a3b77be09b2bc4e88bbfa6dcf7b",
    "9a0c75b5c2ca6315534eff1e6fb3d4247a8a6b292734bcfbcc0de0be72654d8b",
    "966afab6a540e1adfaf82e960eb84cd99ebab2d7e9f518eaa071ac264529968d"
  ].map(raw => Buffer.from(raw, "hex"));

  const pubs = keys.map(key => secp256k1.publicKeyCreate(key, true) as Buffer);

  const msg = "hello world";
  const hash = hash256.digest(Buffer.from(msg, "utf8"));

  it("group factor", () => {
    const L = musig.groupFactor(pubs);
    expect(L).toBeTruthy();
    expect(L).toHaveLength(32);
    expect(L.toString("hex")).toEqual(
      "c0969a83cb86ac063853b7dcf2f45437dc7348a26d3f59c3c9d4569285a8c6da"
    );
  });
});
