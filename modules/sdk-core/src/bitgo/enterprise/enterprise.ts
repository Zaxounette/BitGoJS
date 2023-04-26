/**
 * @prettier
 */
import * as _ from 'lodash';
import { IBaseCoin } from '../baseCoin';
import { BitGoBase } from '../bitgoBase';
import { IEnterprise } from '../enterprise';
import { getFirstPendingTransaction } from '../internal/internal';
import { Settlements, ISettlements, ISettlementAffirmations } from '../settlements';
import { Wallet } from '../wallet';
import { BitGoProofSignatures, EcdsaUtils } from '../utils/tss/ecdsa';
import { DeserializedNtilde } from '../../account-lib/mpc/tss/ecdsa/types';

export class Enterprise implements IEnterprise {
  private readonly _bitgo: BitGoBase;
  private readonly _baseCoin: IBaseCoin;
  readonly id: string;
  readonly name: string;

  constructor(bitgo: BitGoBase, baseCoin: IBaseCoin, enterpriseData: { id: string; name: string }) {
    this._bitgo = bitgo;
    this._baseCoin = baseCoin;
    if (!_.isObject(enterpriseData)) {
      throw new Error('enterpriseData has to be an object');
    }
    if (!_.isString(enterpriseData.id)) {
      throw new Error('enterprise id has to be a string');
    }
    if (!_.isString(enterpriseData.name)) {
      throw new Error('enterprise name has to be a string');
    }
    this.id = enterpriseData.id;
    this.name = enterpriseData.name;
  }

  /**
   * Enterprise URL for v1 methods, such as getting users
   * @param query
   */
  url(query = ''): string {
    return this._bitgo.url(`/enterprise/${this.id}${query}`);
  }

  /**
   * Enterprise URL for v2 methods, such as getting fee address balances
   * @param query
   */
  coinUrl(query = ''): string {
    return this._baseCoin.url(`/enterprise/${this.id}${query}`);
  }

  /**
   * Get the wallets associated with this Enterprise
   * @param params
   */
  async coinWallets(params: Record<string, never> = {}): Promise<Wallet[]> {
    const walletData = (await this._bitgo.get(this._baseCoin.url('/wallet/enterprise/' + this.id)).result()) as any;
    walletData.wallets = walletData.wallets.map((w) => {
      return new Wallet(this._bitgo, this._baseCoin, w);
    });
    return walletData;
  }

  /**
   * Get the users associated with this Enterprise
   * @param params
   */
  async users(params: Record<string, never> = {}): Promise<any> {
    return await this._bitgo.get(this.url('/user')).result();
  }

  /**
   * Get the fee address balance for this Enterprise
   * @param params
   */
  async getFeeAddressBalance(params: Record<string, never> = {}): Promise<any> {
    return await this._bitgo.get(this.coinUrl('/feeAddressBalance')).result();
  }

  /**
   * Add a user to this Enterprise
   * @param params
   */
  async addUser(params: any = {}): Promise<any> {
    return await this._bitgo.post(this.url('/user')).send(params).result();
  }

  /**
   * Remove a user from this Enterprise
   * @param params
   */
  async removeUser(params: any = {}): Promise<any> {
    return await this._bitgo.del(this.url('/user')).send(params).result();
  }

  /**
   * Get the first pending transaction for this Enterprise
   * @param params
   */
  async getFirstPendingTransaction(params: Record<string, never> = {}): Promise<any> {
    return getFirstPendingTransaction({ enterpriseId: this.id }, this._baseCoin, this._bitgo);
  }

  /**
   * Manage settlements for an enterprise
   */
  settlements(): ISettlements {
    return new Settlements(this._bitgo, this.id);
  }

  /**
   * Manage affirmations for an enterprise
   */
  affirmations(): ISettlementAffirmations {
    return this.settlements().affirmations;
  }

  /**
   * Verifies and signs bitgo proofs for the enterprise
   * @param userPassword - enterprise admin's login password
   */
  async verifyEcdsaBitGoChallengeProofs(userPassword: string): Promise<BitGoProofSignatures> {
    return EcdsaUtils.getVerifyAndSignBitGoChallenges(this._bitgo, this.id, userPassword);
  }

  /**
   * Manages all the challenges and signatures and uploads them to enable
   * ECDSA signing on enterprise. Also generates a client side Ntilde challenge
   * if not provided, but note that can take approx. a minute.
   * @param userPassword
   * @param bitgoInstChallengeProofSignature
   * @param bitgoNitroChallengeProofSignature
   * @param challenge
   */
  async uploadAndEnableTssEcdsaSigning(
    userPassword: string,
    bitgoInstChallengeProofSignature: Buffer,
    bitgoNitroChallengeProofSignature: Buffer,
    challenge?: DeserializedNtilde
  ): Promise<void> {
    await EcdsaUtils.initiateChallengesForEnterprise(
      this._bitgo,
      this.id,
      userPassword,
      bitgoInstChallengeProofSignature,
      bitgoNitroChallengeProofSignature,
      challenge
    );
  }

  /**
   * Fetches the existing TSS ECDSA enterprise challenge if one exists.
   * Can be used with uploadAndEnableTssEcdsaSigning to re-sign the
   * enterprise challenge with new signatures.
   */
  async getExistingTssEcdsaChallenge(): Promise<DeserializedNtilde> {
    const urlPath = `/enterprise/${this.id}/tssconfig`;
    const tssConfig = await this._bitgo.get(this._bitgo.url(urlPath, 2)).send().result();
    const enterpriseChallenge = tssConfig?.ecdsa.challenge?.enterprise;
    if (!enterpriseChallenge) {
      throw new Error('No existing ECDSA challenge on the enterprise.');
    }
    return EcdsaUtils.deserializeNtilde({
      ntilde: enterpriseChallenge.ntilde,
      h1: enterpriseChallenge.h1,
      h2: enterpriseChallenge.h2,
    });
  }
}
