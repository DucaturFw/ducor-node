declare module "lotion" {
  type Nullable<T> = { [P in keyof T]: T[P] | null };
  type HandlerType = "tx" | "block" | "query" | "initializer" | "post-listen";

  type DefaultChainInfo = {
    height: number;
    validators: {
      [hash: string]: number;
    };
  };

  type BlockHandler<TState, TTransaction, TChainInfo> = (
    state: TState,
    info: TChainInfo & DefaultChainInfo
  ) => void;

  type TransactionHandler<TState, TTransaction, TChainInfo> = (
    state: TState,
    tx: TTransaction,
    info: TChainInfo & DefaultChainInfo
  ) => void;

  type InitializeHandler<TState> = (state: TState) => void;

  type HandlerFunc<TState, TTransaction, TChainInfo> =
    | TransactionHandler<TState, TTransaction, TChainInfo>
    | InitializeHandler<TState>
    | BlockHandler<TState, TTransaction, TChainInfo>;

  type Plugin<TState, TTransaction, TChainInfo> = {
    type: HandlerType;
    middleware: HandlerFunc<TState, TTransaction, TChainInfo>;
  };

  type Middleware<TState, TTransaction, TChainInfo> =
    | Plugin<TState, TTransaction, TChainInfo>
    | TransactionHandler<TState, TTransaction, TChainInfo>;

  type Middlewares<TState, TTransaction, TChainInfo> =
    | Middleware<TState, TTransaction, TChainInfo>
    | Middleware<TState, TTransaction, TChainInfo>[];

  interface LotionApp<TState, TTransaction, TChainInfo> {
    use(
      middleware: Middlewares<TState, TTransaction, TChainInfo>
    ): LotionApp<TState, TTransaction, TChainInfo>;

    useTx(
      txHandler: TransactionHandler<TState, TTransaction, TChainInfo>
    ): LotionApp<TState, TTransaction, TChainInfo>;
    useBlock(
      blockHandler: BlockHandler<TState, TTransaction, TChainInfo>
    ): LotionApp<TState, TTransaction, TChainInfo>;

    listen(port: number): void;
  }

  interface ILotionInitialConfiguration<TState> {
    initialState: Nullable<TState>;
  }

  interface ILotionModule {
    <TState, TTransaction, TChainInfo>(
      configuration?: ILotionInitialConfiguration<TState>
    ): LotionApp<TState, TTransaction, TChainInfo>;

    connect(): any;
  }

  const Lotion: ILotionModule;
  export = Lotion;
}
