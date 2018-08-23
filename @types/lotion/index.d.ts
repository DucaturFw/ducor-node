declare module "lotion" {
  type Nullable<T> = { [P in keyof T]: T[P] | null };
  type MiddlewareFunc<TState, TTransaction> = (
    state: TState,
    tx: TTransaction
  ) => void;

  interface LotionApp<TState, TTransaction> {
    use(
      middleware: MiddlewareFunc<TState, TTransaction>
    ): LotionApp<TState, TTransaction>;

    listen(port: number): void;
  }

  interface ILotionInitialConfiguration<TState> {
    initialState: Nullable<TState>;
  }

  function lotionFunc<TState, TTransaction>(
    configuration?: ILotionInitialConfiguration<TState>
  ): LotionApp<TState, TTransaction>;

  export default lotionFunc;
}
