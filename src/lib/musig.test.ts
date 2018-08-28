import "jest-extended";
import elliptic = require("elliptic");
import * as musig from "../lib/musig";
const secp256k1 = elliptic.ec("secp256k1");

describe("Musig", () => {
  it("should verify", () => {
    const keys = [
      "5163d545d17016acac014f8ffee3f0a11ace3a3b77be09b2bc4e88bbfa6dcf70",
      "5163d545d17016acac014f8ffee3f0a11ace3a3b77be09b2bc4e88bbfa6dcf71",
      "5163d545d17016acac014f8ffee3f0a11ace3a3b77be09b2bc4e88bbfa6dcf72"
    ].map(raw => secp256k1.keyFromPrivate(raw, "hex"));

    const rnd = [
      "5163d545d17016acac014f8ffee3f0a11ace3a3b77be09b2bc4e88bbfa6dcf73",
      "5163d545d17016acac014f8ffee3f0a11ace3a3b77be09b2bc4e88bbfa6dcf74",
      "5163d545d17016acac014f8ffee3f0a11ace3a3b77be09b2bc4e88bbfa6dcf75"
    ].map(raw => secp256k1.keyFromPrivate(raw, "hex"));

    const pubs = keys.map(k => k.getPublic());
    const nonce = musig.signerGroupNonce(pubs);
    const groupPublicKey = musig.getAggregatePublicKey(nonce, pubs);
    const groupRandomPoint = musig.aggregatedPoint(rnd.map(r => r.getPublic()));
    const message = musig.hash(Buffer.from("Hello world", "utf8"));

    const si = keys.map((priv, index) =>
      musig.getSignature(
        rnd[index].getPrivate(),
        groupPublicKey,
        groupRandomPoint,
        message,
        nonce,
        priv.getPrivate(),
        pubs[index]
      )
    );

    const s = musig.combineSignatures(si, groupRandomPoint);

    console.log("m: ", message.toString("hex"));
    console.log("s.s: ", s.s.umod(secp256k1.curve.n).toString(10));
    console.log("X.x: ", groupPublicKey.x.toString(10));
    console.log("X.y: ", groupPublicKey.y.toString(10));
    console.log("R.x: ", groupRandomPoint.x.toString(10));
    console.log("R.y: ", groupRandomPoint.y.toString(10));

    const sG = secp256k1.curve.g.mul(s.s);
    const h = musig.hashGroupKeyWithPointAndMessage(
      groupRandomPoint,
      groupPublicKey,
      message
    );

    const rr = groupPublicKey.mul(h);
    const rl = groupRandomPoint.add(rr);

    console.log("sg.x: ", sG.x.umod(secp256k1.curve.n).toString(10));
    console.log("sg.y: ", sG.y.umod(secp256k1.curve.n).toString(10));

    console.log("h: ", h.umod(secp256k1.curve.n).toString(10));
    console.log("rr.x: ", rr.x.umod(secp256k1.curve.n).toString(10));
    console.log("rr.y: ", rr.y.umod(secp256k1.curve.n).toString(10));
    console.log("rl: ", rl.x.umod(secp256k1.curve.n).toString(10));
    console.log("rl: ", rl.y.umod(secp256k1.curve.n).toString(10));

    expect(
      musig.verifySignature(message, s, groupPublicKey, groupRandomPoint)
    ).toBeTrue();
  });
});
// const secp256k1 = new elliptic.ec("secp256k1");
// const { hash256 } = require("bcrypto");
// const curve = secp256k1.curve;
// const Ed25519 = elliptic.eddsa("ed25519");

// describe("musig cryptography tests", () => {
//   const keys = [
//     "5163d545d17016acac014f8ffee3f0a11ace3a3b77be09b2bc4e88bbfa6dcf7b",
//     "9a0c75b5c2ca6315534eff1e6fb3d4247a8a6b292734bcfbcc0de0be72654d8b",
//     "966afab6a540e1adfaf82e960eb84cd99ebab2d7e9f518eaa071ac264529968d"
//   ].map(raw => secp256k1.keyFromPrivate(raw, "hex"));

//   const pubs = keys.map(key => key.getPublic());

//   const msg = "hello world";
//   const hash = hash256.digest(Buffer.from(msg, "utf8"));

//   it("group factor", () => {
//     const L = musig.groupFactor(pubs);
//     expect(L).toBeTruthy();
//     expect(L).toHaveLength(32);
//     expect(L.toString("hex")).toEqual(
//       "aa8ae5cf865a9a42c8309c8eb64beb71d827d159c8dca6cfc1cdc65ec60cc605"
//     );
//   });

//   it("group public key", () => {
//     const P = musig.groupPublicKey(pubs);
//     expect(P).toBeTruthy();
//     expect(P.encode("hex")).toEqual(
//       // looks weird or not?
//       // maybe it should be modulated over length?
//       "04b0074bb3edc0166eb237dfb43df27b740890b900543be2f1317f999a9f6bd705593bbcab6e51ed2c3931be2ea5259c3c2ae8a3ec70a1aa3cc5a41ea7a1f19ecd"
//     );
//   });

//   it("deterministic Ks", () => {
//     [
//       "bebbddac729fde58c15c014094e639559c35cd61a01502b961732fc5ccf032a9",
//       "3198e4bba4b3570bad718201115534896fd0d791e4d3c378763517f233eb0960",
//       "2dc923e38ccc86126d0be7051bf060bb0579d83dd2553f4fa029e825273ee703"
//     ]
//       .map((k, index) => [keys[index], k] as [Buffer, string])
//       .forEach(([key, k]) =>
//         expect(musig.deterministinK(hash, key).toString("hex"))
//       );
//   });

//   it("personal random point", () => {
//     expect([
//       "028e1124bf6296d3002188c382c530a011e5044ddcef5f764647ca4a4b911dbf00",
//       "03120c79ceed69a8af64659227dc02acc78219ded39c316a70436a077bb7633881",
//       "024d95b1562256fccb85afbdbfee227e7046ab0071f4968726b72f2930d8d6c6ca"
//     ]).toEqual(
//       keys.map(key => musig.personalRandomPoint(hash, key).encode("hex", true))
//     );
//   });

//   it("decodeble random points", () => {
//     keys.map(key => musig.personalRandomPoint(hash, key)).forEach(point => {
//       expect(point).toHaveProperty("x");
//       expect(point).toHaveProperty("y");
//     });
//   });

//   it("group random point", () => {
//     expect(
//       Buffer.from(
//         musig
//           .groupRandomPoint(
//             ...keys.map(key => musig.personalRandomPoint(hash, key))
//           )
//           .encode()
//       ).toString("hex")
//     ).toEqual(
//       "04ef22652138cc7a3a70f28d00b33cf71986eebb14b4dbf6928f04327a3af8400141d11e2b39d52dfc718016edb9399f8200a8b8c5a726006c80d269aa624a08cc"
//     );
//   });

//   it("participate signature test", () => {
//     const L = musig.groupFactor(pubs);
//     const Rn = keys.map(key => musig.personalRandomPoint(hash, key));
//     const R = musig.groupRandomPoint(...Rn);
//     const P = musig.groupPublicKey(pubs, L);

//     expect([
//       "f37e075bac6320d4e8443d8b47785c272ec9c4dd27988de284c2e89e6dea1aec",
//       "7a61cc0104c9bf702730b2c2e7fb65fa4acdffdfd6bf8d20019a7bd5ec229ec7",
//       "559175a04cdc4208f8205be13a89d0e36dfabe10c4359cff1f1cbc60546d87dd"
//     ]).toEqual(
//       keys.map((key, index) =>
//         musig
//           .sign(hash, pubs[index], key, L, R, P)
//           .toBuffer("be")
//           .toString("hex")
//       )
//     );
//   });

//   it("final signature", () => {
//     const L = musig.groupFactor(pubs);
//     const Rn = keys.map(key => musig.personalRandomPoint(hash, key));
//     const R = musig.groupRandomPoint(...Rn);
//     const P = musig.groupPublicKey(pubs, L);
//     const Si = keys.map((key, index) =>
//       musig.sign(hash, pubs[index], key, L, R, P)
//     );

//     const s = musig
//       .combine(Si)
//       .toBuffer("be")
//       .toString("hex");

//     expect(s).toEqual(
//       "c37148fcfe09224e07954c2f69fd93062ce3a5e7134517c5e5a7c247de44004f"
//     );
//   });

//   it("verify", () => {
//     const L = musig.groupFactor(pubs);
//     const Rn = keys.map(key => musig.personalRandomPoint(hash, key));
//     const R = musig.groupRandomPoint(...Rn);
//     const P = musig.groupPublicKey(pubs, L);
//     const Si = keys.map((key, index) =>
//       musig.sign(hash, pubs[index], key, L, R, P)
//     );

//     const s = musig.combine(Si);

//     expect(musig.verify(hash, s, R, P)).toBeTrue();
//   });
// });
