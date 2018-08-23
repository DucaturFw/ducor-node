import lotion from "lotion";

export interface IState {
  count: number;
}

export interface ITransaction {}

const app = lotion<IState, ITransaction>({
  initialState: {
    count: 0
  }
});

app.use((state, tx) => state.count++);

app.listen(3000);
