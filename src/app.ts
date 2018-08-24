import * as lotion from "lotion";
import { schnorr } from "./schnorr";

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

const app = lotion<IState, ITransaction, IChainInfo>({
  initialState: {
    count: 0
  }
});

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
  schnorr.verify(msg, sig, pub);
});
app.listen(3000);
