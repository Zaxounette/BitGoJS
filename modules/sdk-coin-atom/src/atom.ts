import {
  BaseCoin,
  BaseTransaction,
  BitGoBase,
  Ecdsa,
  Environments,
  ExplanationResult,
  InvalidAddressError,
  InvalidMemoIdError,
  KeyPair,
  MPCAlgorithm,
  ParsedTransaction,
  ParseTransactionOptions,
  SignedTransaction,
  SigningError,
  SignTransactionOptions,
  TransactionType,
  UnexpectedAddressError,
  VerifyAddressOptions,
  VerifyTransactionOptions,
  ECDSAMethodTypes,
  ECDSA,
} from '@bitgo/sdk-core';
import { BaseCoin as StaticsBaseCoin, CoinFamily, coins } from '@bitgo/statics';
import { bip32 } from '@bitgo/utxo-lib';
import { BigNumber } from 'bignumber.js';
import { createHash, Hash, randomBytes } from 'crypto';
import * as _ from 'lodash';
import { TransactionBuilderFactory } from './lib/transactionBuilderFactory';
import utils from './lib/utils';
import url from 'url';
import querystring from 'querystring';
import { isInteger } from 'lodash';
import { KeyPair as AtomKeyPair, Transaction } from './lib';
import * as request from 'superagent';
import { Buffer } from 'buffer';
import Keccak from 'keccak';
import { FeeData, SendMessage } from './lib/iface';
import { Coin } from '@cosmjs/stargate';
import { GAS_AMOUNT, GAS_LIMIT } from './lib/constants';

/**
 * Atom accounts support memo Id based addresses
 */
interface AddressDetails {
  address: string;
  memoId?: string | undefined;
}

/**
 * Atom accounts support memo Id based addresses
 */
interface AtomCoinSpecific {
  rootAddress: string;
}

interface RecoveryOptions {
  userKey?: string; // Box A
  backupKey?: string; // Box B
  bitgoKey: string; // Box C
  recoveryDestination: string;
  krsProvider?: string;
  walletPassphrase?: string;
  startingScanIndex?: number;
  scan?: number;
}

interface AtomTx {
  serializedTx: string;
  scanIndex: number;
}

export class Atom extends BaseCoin {
  protected readonly _staticsCoin: Readonly<StaticsBaseCoin>;
  protected constructor(bitgo: BitGoBase, staticsCoin?: Readonly<StaticsBaseCoin>) {
    super(bitgo);

    if (!staticsCoin) {
      throw new Error('missing required constructor parameter staticsCoin');
    }

    this._staticsCoin = staticsCoin;
  }

  static createInstance(bitgo: BitGoBase, staticsCoin?: Readonly<StaticsBaseCoin>): BaseCoin {
    return new Atom(bitgo, staticsCoin);
  }

  /** @inheritDoc **/
  getBaseFactor(): string | number {
    return 1e6;
  }

  /** @inheritDoc **/
  getChain(): string {
    return this._staticsCoin.name;
  }

  /** @inheritDoc **/
  getFamily(): CoinFamily {
    return this._staticsCoin.family;
  }

  /** @inheritDoc **/
  getFullName(): string {
    return this._staticsCoin.fullName;
  }

  /** @inheritDoc */
  supportsTss(): boolean {
    return true;
  }

  /** @inheritDoc **/
  getMPCAlgorithm(): MPCAlgorithm {
    return 'ecdsa';
  }

  /** @inheritDoc **/
  isValidPub(pub: string): boolean {
    return utils.isValidPublicKey(pub);
  }

  /** @inheritDoc **/
  isValidPrv(prv: string): boolean {
    return utils.isValidPrivateKey(prv);
  }

  getBuilder(): TransactionBuilderFactory {
    return new TransactionBuilderFactory(coins.get(this.getChain()));
  }

  /** @inheritDoc **/
  isValidAddress(address: string): boolean {
    return utils.isValidAddress(address) || utils.isValidValidatorAddress(address);
  }

  /** @inheritDoc **/
  async verifyTransaction(params: VerifyTransactionOptions): Promise<boolean> {
    let totalAmount = new BigNumber(0);
    const coinConfig = coins.get(this.getChain());
    const { txPrebuild, txParams } = params;
    const rawTx = txPrebuild.txHex;
    if (!rawTx) {
      throw new Error('missing required tx prebuild property txHex');
    }
    const transaction = await new TransactionBuilderFactory(coinConfig).from(rawTx).build();
    const explainedTx = transaction.explainTransaction();

    if (txParams.recipients && txParams.recipients.length > 0) {
      const filteredRecipients = txParams.recipients?.map((recipient) => _.pick(recipient, ['address', 'amount']));
      const filteredOutputs = explainedTx.outputs.map((output) => _.pick(output, ['address', 'amount']));

      if (!_.isEqual(filteredOutputs, filteredRecipients)) {
        throw new Error('Tx outputs does not match with expected txParams recipients');
      }
      // WithdrawDelegatorRewards transaction doesn't have amount
      if (transaction.type !== TransactionType.StakingWithdraw) {
        for (const recipients of txParams.recipients) {
          totalAmount = totalAmount.plus(recipients.amount);
        }
        if (!totalAmount.isEqualTo(explainedTx.outputAmount)) {
          throw new Error('Tx total amount does not match with expected total amount field');
        }
      }
    }
    return true;
  }

  /** @inheritDoc **/
  async parseTransaction(params: ParseTransactionOptions & { txHex: string }): Promise<ParsedTransaction> {
    const transactionExplanation = await this.explainTransaction({ txHex: params.txHex });
    if (!transactionExplanation) {
      throw new Error('Invalid transaction');
    }

    if (transactionExplanation.outputs.length <= 0) {
      return {
        inputs: [],
        outputs: [],
      };
    }
    const senderAddress = transactionExplanation.outputs[0].address;
    const feeAmount = new BigNumber(transactionExplanation.fee.fee === '' ? '0' : transactionExplanation.fee.fee);
    const inputs = [
      {
        address: senderAddress,
        amount: new BigNumber(transactionExplanation.outputAmount).plus(feeAmount).toFixed(),
      },
    ];
    const outputs = transactionExplanation.outputs.map((output) => {
      return {
        address: output.address,
        amount: new BigNumber(output.amount).toFixed(),
      };
    });
    return {
      inputs,
      outputs,
    };
  }

  /** @inheritDoc **/
  async explainTransaction(options: { txHex: string }): Promise<ExplanationResult> {
    if (!options.txHex) {
      throw new Error('missing required txHex parameter');
    }
    try {
      const transactionBuilder = new TransactionBuilderFactory(coins.get(this.getChain())).from(options.txHex);
      const transaction = await transactionBuilder.build();
      return transaction.explainTransaction();
    } catch (e) {
      throw new Error('Invalid transaction: ' + e.message);
    }
  }

  /** @inheritDoc **/
  generateKeyPair(seed?: Buffer): KeyPair {
    if (!seed) {
      // An extended private key has both a normal 256 bit private key and a 256
      // bit chain code, both of which must be random. 512 bits is therefore the
      // maximum entropy and gives us maximum security against cracking.
      seed = randomBytes(512 / 8);
    }
    const extendedKey = bip32.fromSeed(seed);
    return {
      pub: extendedKey.neutered().toBase58(),
      prv: extendedKey.toBase58(),
    };
  }

  /**
   * Sign a transaction with a single private key
   * @param params parameters in the form of { txPrebuild: {txHex}, prv }
   * @returns signed transaction in the form of { txHex }
   */
  async signTransaction(
    params: SignTransactionOptions & { txPrebuild: { txHex: string }; prv: string }
  ): Promise<SignedTransaction> {
    const txHex = params?.txPrebuild?.txHex;
    const privateKey = params?.prv;
    if (!txHex) {
      throw new SigningError('missing required txPrebuild parameter: params.txPrebuild.txHex');
    }
    if (!privateKey) {
      throw new SigningError('missing required prv parameter: params.prv');
    }
    const txBuilder = new TransactionBuilderFactory(coins.get(this.getChain())).from(params.txPrebuild.txHex);
    txBuilder.sign({ key: params.prv });
    const transaction: BaseTransaction = await txBuilder.build();
    if (!transaction) {
      throw new SigningError('Failed to build signed transaction');
    }
    const serializedTx = transaction.toBroadcastFormat();
    return {
      txHex: serializedTx,
    };
  }

  /**
   * Builds a funds recovery transaction without BitGo
   * @param {RecoveryOptions} params parameters needed to construct and
   * (maybe) sign the transaction
   *
   * @returns {AtomTx} the serialized transaction hex string and index
   * of the address being swept
   */
  async recover(params: RecoveryOptions): Promise<AtomTx> {
    let publicKey: string;
    // Step 1: Check if params contains the required parameters
    if (!params.bitgoKey) {
      throw new Error('missing bitgoKey');
    }

    if (!params.recoveryDestination || !this.isValidAddress(params.recoveryDestination)) {
      throw new Error('invalid recoveryDestination');
    }

    // Step 2: Fetch the starting scan index if its present (else 0)
    let startIdx = params.startingScanIndex;
    if (_.isUndefined(startIdx)) {
      startIdx = 0;
    } else if (!isInteger(startIdx) || startIdx < 0) {
      throw new Error('Invalid starting index to scan for addresses');
    }

    // Step 3: Fetch the number of iterations from params if its present (else 20)
    let numIteration = params.scan;
    if (_.isUndefined(numIteration)) {
      // magic number ? Why 20 ?
      numIteration = 20;
    } else if (!isInteger(numIteration) || numIteration <= 0) {
      throw new Error('Invalid scanning factor');
    }

    // Step 4: Fetch the bitgo key from params
    const bitgoKey = params.bitgoKey.replace(/\s/g, '');

    // Step 5: Instantiate the ECDSA signer
    const MPC = new Ecdsa();

    // Step 6: For each account from the starting index till numIterations + starting index, fetch the build tx details
    for (let i = startIdx; i < numIteration + startIdx; i++) {
      const currPath = `m/${i}`;
      publicKey = MPC.deriveUnhardened(bitgoKey, currPath).slice(0, 66);
      const senderAddress = this.getAddressFromPublicKey(publicKey);
      const balance = await this.getAccountBalance(senderAddress);

      if (Number(balance) <= 0) {
        continue;
      }

      const accountNumber = await this.getAccountNumber(senderAddress);
      const chainId = await this.getChainId();
      const gasBudget: FeeData = {
        amount: [{ denom: 'uatom', amount: GAS_AMOUNT }],
        gasLimit: GAS_LIMIT,
      };
      const actualBalance = Number(balance) - Number(gasBudget.amount[0].amount);
      const amount: Coin[] = [
        {
          denom: 'uatom',
          amount: actualBalance.toString(),
        },
      ];

      const sendMessage: SendMessage[] = [
        {
          fromAddress: senderAddress,
          toAddress: params.recoveryDestination,
          amount: amount,
        },
      ];

      // Step 7: Build the unsigned tx
      const txnBuilder = this.getBuilder().getTransferBuilder();
      txnBuilder
        .messages(sendMessage)
        .gasBudget(gasBudget)
        .publicKey(publicKey)
        .accountNumber(Number(accountNumber))
        .chainId(chainId);
      const unsignedTransaction = (await txnBuilder.build()) as Transaction;
      let serializedTx = unsignedTransaction.toBroadcastFormat();
      const signableHex = unsignedTransaction.signablePayload.toString('hex');

      // Step 8: Validate necessary parameters required for performing recovery
      if (!params.userKey) {
        throw new Error('missing userKey');
      }
      if (!params.backupKey) {
        throw new Error('missing backupKey');
      }
      if (!params.walletPassphrase) {
        throw new Error('missing wallet passphrase');
      }

      const userKey = params.userKey.replace(/\s/g, '');
      const backupKey = params.backupKey.replace(/\s/g, '');
      const [userKeyCombined, backupKeyCombined] = ((): [
        ECDSAMethodTypes.KeyCombined | undefined,
        ECDSAMethodTypes.KeyCombined | undefined
      ] => {
        const [userKeyCombined, backupKeyCombined] = this.getKeyCombinedFromTssKeyShares(
          userKey,
          backupKey,
          params.walletPassphrase
        );
        return [userKeyCombined, backupKeyCombined];
      })();

      if (!userKeyCombined || !backupKeyCombined) {
        throw new Error('Missing key combined shares for user or backup');
      }

      // Step 9: Sign the tx
      const signature = await this.signRecoveryTSS(userKeyCombined, backupKeyCombined, signableHex);
      const atomKeyPair = new AtomKeyPair({ pub: publicKey });
      txnBuilder.addSignature({ pub: atomKeyPair.getKeys().pub }, Buffer.from(signature.r + signature.s, 'hex'));
      const signedTransaction = await txnBuilder.build();
      serializedTx = signedTransaction.toBroadcastFormat();

      return { serializedTx: serializedTx, scanIndex: i };
    }
    throw new Error('Did not find an address with funds to recover');
  }

  /**
   * Get balance from public node
   */
  protected async getBalanceFromNode(senderAddress: string): Promise<request.Response> {
    const nodeUrl = this.getPublicNodeUrl();
    const getBalancePath = 'cosmos/bank/v1beta1/balances/';
    const fullEndpoint = nodeUrl + getBalancePath + senderAddress;
    try {
      return await request.get(fullEndpoint).send();
    } catch (e) {
      console.debug(e);
    }
    throw new Error(`Unable to call endpoint ${getBalancePath + senderAddress} from node: ${nodeUrl}`);
  }

  /**
   * Helper to fetch chainId
   */
  protected async getChainId(): Promise<string> {
    const response = await this.getChainIdFromNode();
    if (response.status !== 200) {
      throw new Error('Account not found');
    }
    return response.body.block.header.chain_id;
  }

  /**
   * Get chain id from public node
   */
  protected async getChainIdFromNode(): Promise<request.Response> {
    const nodeUrl = this.getPublicNodeUrl();
    const getLatestBlockPath = 'cosmos/base/tendermint/v1beta1/blocks/latest';
    const fullEndpoint = nodeUrl + getLatestBlockPath;
    try {
      return await request.get(fullEndpoint).send();
    } catch (e) {
      console.debug(e);
    }
    throw new Error(`Unable to call endpoint ${getLatestBlockPath} from node: ${nodeUrl}`);
  }

  /**
   * Helper to fetch account number
   */
  protected async getAccountNumber(senderAddress: string): Promise<string> {
    const response = await this.getAccountFromNode(senderAddress);
    if (response.status !== 200) {
      throw new Error('Account not found');
    }
    return response.body.account.account_number;
  }

  /**
   * Get account number from public node
   */
  protected async getAccountFromNode(senderAddress: string): Promise<request.Response> {
    const nodeUrl = this.getPublicNodeUrl();
    const getAccountPath = 'cosmos/auth/v1beta1/accounts/';
    const fullEndpoint = nodeUrl + getAccountPath + senderAddress;
    try {
      return await request.get(fullEndpoint).send();
    } catch (e) {
      console.debug(e);
    }
    throw new Error(`Unable to call endpoint ${getAccountPath + senderAddress} from node: ${nodeUrl}`);
  }

  /**
   * Helper to fetch account balance
   */
  protected async getAccountBalance(senderAddress: string): Promise<string> {
    const response = await this.getBalanceFromNode(senderAddress);
    if (response.status !== 200) {
      throw new Error('Account not found');
    }
    return response.body.balances[0].amount;
  }

  /**
   * Get the public node url from the Environments constant we have defined
   */
  protected getPublicNodeUrl(): string {
    return Environments[this.bitgo.getEnv()].atomNodeUrl;
  }

  getAddressFromPublicKey(pubKey: string): string {
    return new AtomKeyPair({ pub: pubKey }).getAddress();
  }

  /** @inheritDoc **/
  async isWalletAddress(params: VerifyAddressOptions): Promise<boolean> {
    const addressDetails = this.getAddressDetails(params.address);

    if (!this.isValidAddress(addressDetails.address)) {
      throw new InvalidAddressError(`invalid address: ${addressDetails.address}`);
    }
    const rootAddress = (params.coinSpecific as AtomCoinSpecific).rootAddress;
    if (addressDetails.address !== rootAddress) {
      throw new UnexpectedAddressError(`address validation failure: ${addressDetails.address} vs ${rootAddress}`);
    }
    return true;
  }

  getHashFunction(): Hash {
    return createHash('sha256');
  }

  /**
   * Process address into address and memo id
   *
   * @param address the address
   * @returns object containing address and memo id
   */
  getAddressDetails(address: string): AddressDetails {
    const destinationDetails = url.parse(address);
    const destinationAddress = destinationDetails.pathname || '';

    // address doesn't have a memo id
    if (destinationDetails.pathname === address) {
      return {
        address: address,
        memoId: undefined,
      };
    }

    if (!destinationDetails.query) {
      throw new InvalidAddressError(`invalid address: ${address}`);
    }

    const queryDetails = querystring.parse(destinationDetails.query);
    if (!queryDetails.memoId) {
      // if there are more properties, the query details need to contain the memo id property
      throw new InvalidAddressError(`invalid address: ${address}`);
    }

    if (Array.isArray(queryDetails.memoId)) {
      throw new InvalidAddressError(
        `memoId may only be given at most once, but found ${queryDetails.memoId.length} instances in address ${address}`
      );
    }

    if (Array.isArray(queryDetails.memoId) && queryDetails.memoId.length !== 1) {
      // valid addresses can only contain one memo id
      throw new InvalidAddressError(`invalid address '${address}', must contain exactly one memoId`);
    }

    const [memoId] = _.castArray(queryDetails.memoId) || undefined;
    if (!this.isValidMemoId(memoId)) {
      throw new InvalidMemoIdError(`invalid address: '${address}', memoId is not valid`);
    }

    return {
      address: destinationAddress,
      memoId,
    };
  }

  /**
   * Return boolean indicating whether a memo id is valid
   *
   * @param memoId memo id
   * @returns true if memo id is valid
   */
  isValidMemoId(memoId: string): boolean {
    let memoIdNumber;
    try {
      memoIdNumber = new BigNumber(memoId);
    } catch (e) {
      return false;
    }
    return memoIdNumber.gte(0);
  }

  private getKeyCombinedFromTssKeyShares(
    userPublicOrPrivateKeyShare: string,
    backupPrivateOrPublicKeyShare: string,
    walletPassphrase?: string
  ): [ECDSAMethodTypes.KeyCombined, ECDSAMethodTypes.KeyCombined] {
    let backupPrv;
    let userPrv;
    try {
      backupPrv = this.bitgo.decrypt({
        input: backupPrivateOrPublicKeyShare,
        password: walletPassphrase,
      });
      userPrv = this.bitgo.decrypt({
        input: userPublicOrPrivateKeyShare,
        password: walletPassphrase,
      });
    } catch (e) {
      throw new Error(`Error decrypting backup keychain: ${e.message}`);
    }

    const userSigningMaterial = JSON.parse(userPrv) as ECDSAMethodTypes.SigningMaterial;
    const backupSigningMaterial = JSON.parse(backupPrv) as ECDSAMethodTypes.SigningMaterial;

    if (!userSigningMaterial.backupNShare) {
      throw new Error('Invalid user key - missing backupNShare');
    }

    if (!backupSigningMaterial.userNShare) {
      throw new Error('Invalid backup key - missing userNShare');
    }

    const MPC = new Ecdsa();

    const userKeyCombined = MPC.keyCombine(userSigningMaterial.pShare, [
      userSigningMaterial.bitgoNShare,
      userSigningMaterial.backupNShare,
    ]);
    const backupKeyCombined = MPC.keyCombine(backupSigningMaterial.pShare, [
      backupSigningMaterial.bitgoNShare,
      backupSigningMaterial.userNShare,
    ]);

    if (
      userKeyCombined.xShare.y !== backupKeyCombined.xShare.y ||
      userKeyCombined.xShare.chaincode !== backupKeyCombined.xShare.chaincode
    ) {
      throw new Error('Common keychains do not match');
    }

    return [userKeyCombined, backupKeyCombined];
  }

  private async signRecoveryTSS(
    userKeyCombined: ECDSA.KeyCombined,
    backupKeyCombined: ECDSA.KeyCombined,
    txHex: string
  ): Promise<ECDSAMethodTypes.Signature> {
    const MPC = new Ecdsa();
    const signerOneIndex = userKeyCombined.xShare.i;
    const signerTwoIndex = backupKeyCombined.xShare.i;

    const userXShare: ECDSAMethodTypes.XShareWithNtilde = (
      await MPC.appendChallenge(userKeyCombined.xShare, userKeyCombined.yShares[signerTwoIndex])
    ).xShare;
    const userYShare: ECDSAMethodTypes.YShareWithNtilde = {
      ...userKeyCombined.yShares[signerTwoIndex],
      ntilde: userXShare.ntilde,
      h1: userXShare.h1,
      h2: userXShare.h2,
    };
    const backupXShare: ECDSAMethodTypes.XShareWithNtilde = {
      ...backupKeyCombined.xShare,
      ntilde: userXShare.ntilde,
      h1: userXShare.h1,
      h2: userXShare.h2,
    };
    const backupYShare: ECDSAMethodTypes.YShareWithNtilde = {
      ...backupKeyCombined.yShares[signerOneIndex],
      ntilde: backupXShare.ntilde,
      h1: backupXShare.h1,
      h2: backupXShare.h2,
    };

    const signShares: ECDSA.SignShareRT = await MPC.signShare(userXShare, userYShare);

    let signConvertS21: ECDSA.SignConvertRT = await MPC.signConvert({
      xShare: backupXShare,
      yShare: backupYShare, // YShare corresponding to the other participant signerOne
      kShare: signShares.kShare,
    });

    const signConvertS12: ECDSA.SignConvertRT = await MPC.signConvert({
      aShare: signConvertS21.aShare,
      wShare: signShares.wShare,
    });

    signConvertS21 = await MPC.signConvert({
      muShare: signConvertS12.muShare,
      bShare: signConvertS21.bShare,
    });

    const [signCombineOne, signCombineTwo] = [
      MPC.signCombine({
        gShare: signConvertS12.gShare as ECDSA.GShare,
        signIndex: {
          i: (signConvertS12.muShare as ECDSA.MUShare).i,
          j: (signConvertS12.muShare as ECDSA.MUShare).j,
        },
      }),
      MPC.signCombine({
        gShare: signConvertS21.gShare as ECDSA.GShare,
        signIndex: {
          i: (signConvertS21.muShare as ECDSA.MUShare).i,
          j: (signConvertS21.muShare as ECDSA.MUShare).j,
        },
      }),
    ];

    const MESSAGE = Buffer.from(txHex, 'hex');

    const [signA, signB] = [
      MPC.sign(MESSAGE, signCombineOne.oShare, signCombineTwo.dShare, Keccak('keccak256')),
      MPC.sign(MESSAGE, signCombineTwo.oShare, signCombineOne.dShare, Keccak('keccak256')),
    ];

    const signature = MPC.constructSignature([signA, signB]);

    return signature;
  }
}
