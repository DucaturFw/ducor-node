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

  it("group public key", () => {
    const P = musig.groupPublicKey(pubs);
    expect(P).toBeTruthy();
    expect(P.encode("hex")).toEqual(
      // looks weird or not?
      // maybe it should be modulated over length?
      "04b0074bb3edc0166eb237dfb43df27b740890b900543be2f1317f999a9f6bd705593bbcab6e51ed2c3931be2ea5259c3c2ae8a3ec70a1aa3cc5a41ea7a1f19ecd"
    );
  });

  it("deterministic Ks", () => {
    [
      "bebbddac729fde58c15c014094e639559c35cd61a01502b961732fc5ccf032a9",
      "3198e4bba4b3570bad718201115534896fd0d791e4d3c378763517f233eb0960",
      "2dc923e38ccc86126d0be7051bf060bb0579d83dd2553f4fa029e825273ee703"
    ]
      .map((k, index) => [keys[index], k] as [Buffer, string])
      .forEach(([key, k]) =>
        expect(musig.deterministinK(hash, key).toString("hex"))
      );
  });

  it("personal random point", () => {
    expect([
      "028e1124bf6296d3002188c382c530a011e5044ddcef5f764647ca4a4b911dbf00",
      "03120c79ceed69a8af64659227dc02acc78219ded39c316a70436a077bb7633881",
      "024d95b1562256fccb85afbdbfee227e7046ab0071f4968726b72f2930d8d6c6ca"
    ]).toEqual(
      keys.map(key => musig.personalRandomPoint(hash, key).encode("hex", true))
    );
  });

  it("decodeble random points", () => {
    keys.map(key => musig.personalRandomPoint(hash, key)).forEach(point => {
      expect(point).toHaveProperty("x");
      expect(point).toHaveProperty("y");
    });
  });

  it("group random point", () => {
    expect(
      Buffer.from(
        musig
          .groupRandomPoint(
            ...keys.map(key => musig.personalRandomPoint(hash, key))
          )
          .encode()
      ).toString("hex")
    ).toEqual(
      "04ef22652138cc7a3a70f28d00b33cf71986eebb14b4dbf6928f04327a3af8400141d11e2b39d52dfc718016edb9399f8200a8b8c5a726006c80d269aa624a08cc"
    );
  });

  it("participate signature test", () => {
    const L = musig.groupFactor(pubs);
    const Rn = keys.map(key => musig.personalRandomPoint(hash, key));
    const R = musig.groupRandomPoint(...Rn);
    const P = musig.groupPublicKey(pubs, L);

    expect([
      "0c6f401a99b1d1244344a831c30f906ed6e2afa036102d484966681d5c0b0d295e2e7461e4cfbc04130bdb506a588c97e5a2e813d80ef628a7670e498544afe189a16e6c9dadb686fc46df3b1b9391e2656a88b90c68456fe30172c36c69d246",
      "2024d16ee700ffd88df518394513fda27083db4f7d6ca8c3d0cc2a99d39cd18dbb8232a725ed2236ddbce0fab4b607959ebfb8f777fb8e32be6908e189fd1dde2d29083e6381cf5351fea4db19309bf2c7a218199ec8c1372d76f3889bba0e48",
      "1ea2ab7c5efaf20d30e422f73a9600988d07a5844fe7a4cedae4243bc876b06f2763b499c919e67d6cf2d5a38d8ae9bd4fa7eaeaa5e653d19cbd0aeb4fd8f4834891dc641dbeb4be3169352d35b168c113a55266a900e155d9c1e0f57bd91afe"
    ]).toEqual(
      keys.map((key, index) =>
        musig
          .sign(hash, pubs[index], key, L, R, P)
          .toBuffer("be")
          .toString("hex")
      )
    );
  });

  it("final signature", () => {
    const L = musig.groupFactor(pubs);
    const Rn = keys.map(key => musig.personalRandomPoint(hash, key));
    const R = musig.groupRandomPoint(...Rn);
    const P = musig.groupPublicKey(pubs, L);
    const Si = keys.map((key, index) =>
      musig.sign(hash, pubs[index], key, L, R, P)
    );

    const s = musig
      .combine(Si)
      .toBuffer("be")
      .toString("hex");

    expect(s).toEqual(
      "4b36bd05dfadc30a021de36242b98ea9d46e307403647adaf516b6f2f81e8f2641145ba2d3d6c4b85dbb91eeac997dead40a8bf5f5f0d82d028d22165f1ac242ff5c530f1eee3a987faeb9436a75969640b1f3395431e7fcea3a474183fcfb8c"
    );
  });

  it("verify", () => {
    const L = musig.groupFactor(pubs);
    const Rn = keys.map(key => musig.personalRandomPoint(hash, key));
    const R = musig.groupRandomPoint(...Rn);
    const P = musig.groupPublicKey(pubs, L);
    const Si = keys.map((key, index) =>
      musig.sign(hash, pubs[index], key, L, R, P)
    );

    const s = musig.combine(Si);

    console.log(musig.verify(hash, s, R, P));
  });
});
