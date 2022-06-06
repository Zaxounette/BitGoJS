import { BaseCoin as CoinConfig } from '@bitgo/statics';
import { BaseKey } from '@bitgo/sdk-core/src/account-lib/baseCoin/iface';
import { NotImplementedError } from '@bitgo/sdk-core/src/account-lib/baseCoin/errors';
import { TransactionBuilder } from './transactionBuilder';
import { Transaction } from './transaction';
import { TransactionType } from '@bitgo/sdk-core/src/account-lib/baseCoin';

export class TransferBuilder extends TransactionBuilder {
  constructor(_coinConfig: Readonly<CoinConfig>) {
    super(_coinConfig);
  }

  protected get transactionType(): TransactionType {
    return TransactionType.WalletInitialization;
  }

  /** @inheritdoc */
  protected buildAvaxpTransaction(): Transaction {
    throw new NotImplementedError('buildImplementation not implemented');
  }

  /** @inheritdoc */
  protected async buildImplementation(): Promise<Transaction> {
    throw new NotImplementedError('buildImplementation not implemented');
  }

  /** @inheritdoc */
  protected fromImplementation(rawTransaction: string): Transaction {
    throw new NotImplementedError('fromImplementation not implemented');
  }

  /** @inheritdoc */
  protected signImplementation(key: BaseKey): Transaction {
    throw new NotImplementedError('signImplementation not implemented');
  }
}