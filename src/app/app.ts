import * as lotion from "lotion";
import * as musig from "../lib/musig";

export interface IState {
  count: number;
}
export interface ITransaction {
  sig: string;
  msg: string;
  pub: string;
}
export interface IChainInfo {
  foo: number;
}

console.log("Intitialize lotion app");
const app = lotion<IState, ITransaction, IChainInfo>({
  initialState: {
    count: 0
  }
});

console.log("Configure handlers");
app.use((state, tx) => {
  let msg: Buffer, sig: Buffer, pub: Buffer;
  try {
    msg = Buffer.from(tx.msg, "utf8");
  } catch (e) {
    console.error("incorrect msg", tx.msg, e);
    throw e;
  }
  sig = Buffer.from(tx.sig, "hex");
  pub = Buffer.from(tx.pub, "hex");
  // schnorr.verify(msg, sig, pub);
});

console.log("Start node");
app.listen(3000).then(console.log);
