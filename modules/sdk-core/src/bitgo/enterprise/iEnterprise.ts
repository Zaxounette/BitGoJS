import { ISettlementAffirmations, ISettlements } from '../settlements';
import { IWallet } from '../wallet';
import { Buffer } from 'buffer';
import { BitGoProofSignatures } from '../utils/tss/ecdsa';
import { DeserializedNtilde } from '../../account-lib/mpc/tss/ecdsa/types';

export interface IEnterprise {
  addUser(params?: any): Promise<any>;
  coinUrl(query?: string): string;
  coinWallets(params?: Record<string, never>): Promise<IWallet[]>;
  getFeeAddressBalance(params?: Record<string, never>): Promise<any>;
  getFirstPendingTransaction(params?: Record<string, never>): Promise<any>;
  removeUser(params?: any): Promise<any>;
  url(query?: string): string;
  users(params?: Record<string, never>): Promise<any>;
  settlements(): ISettlements;
  affirmations(): ISettlementAffirmations;
  verifyEcdsaBitGoChallengeProofs(userPassword: string): Promise<BitGoProofSignatures>;
  uploadAndEnableTssEcdsaSigning(
    userPassword: string,
    bitgoInstChallengeProofSignature: Buffer,
    bitgoNitroChallengeProofSignature: Buffer,
    challenge?: DeserializedNtilde
  ): Promise<void>;
  getExistingTssEcdsaChallenge(): Promise<DeserializedNtilde>;
}
