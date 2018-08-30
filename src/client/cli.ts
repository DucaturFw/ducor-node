import { connect } from "lotion";
import { IState, ITransaction } from "../app/app";

async function run() {
  const { state, send } = await connect<IState, ITransaction>(
    "f08c60e97ea0b11fc363a023f26160046ee3a8e47a6603ebc601600558114dea"
  );

  // const key = secp256k1.generatePrivateKey() as Buffer;
  // const pub = secp256k1.publicKeyCreate(key, true) as Buffer;
  // const msg = "hello world";
  // const hash = hash256.digest(Buffer.from(msg, "utf8"));
  // const sig = schnorr.sign(hash, key);

  // const tx = {
  //   msg,
  //   pub: pub.toString("hex"),
  //   sig: Buffer.from(sig.toDER()).toString("hex")
  // };

  // console.log(tx, await send(tx));
}

run();
