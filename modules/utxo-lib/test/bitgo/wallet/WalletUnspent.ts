import * as assert from 'assert';

import { Transaction, networks } from '../../../src';
import {
  isWalletUnspent,
  isUnspentWithPrevTx,
  formatOutputId,
  getOutputIdForInput,
  parseOutputId,
  TxOutPoint,
  Unspent,
  createTransactionBuilderForNetwork,
  getInternalChainCode,
  getExternalChainCode,
  addToTransactionBuilder,
  signInputWithUnspent,
  WalletUnspentSigner,
  outputScripts,
  unspentSum,
  getWalletAddress,
  verifySignatureWithUnspent,
  toTNumber,
  UnspentWithPrevTx,
  WalletUnspent,
  UtxoTransaction,
  createPsbtForNetwork,
  createPsbtFromTransaction,
  addWalletUnspentToPsbt,
  addWalletOutputToPsbt,
  toPrevOutput,
  KeyName,
} from '../../../src/bitgo';

import { getDefaultWalletKeys } from '../../testutil';
import { mockWalletUnspent } from './util';
import { defaultTestOutputAmount } from '../../transaction_util';

const CHANGE_INDEX = 100;
const FEE = BigInt(100);

describe('WalletUnspent', function () {
  const network = networks.bitcoin;
  const walletKeys = getDefaultWalletKeys();
  const hash = Buffer.alloc(32).fill(0xff);
  hash[0] = 0; // show endianness
  const input = { hash, index: 0 };
  const expectedOutPoint: TxOutPoint = {
    txid: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00',
    vout: 0,
  };

  it('parses and formats txid', function () {
    assert.deepStrictEqual(getOutputIdForInput(input), expectedOutPoint);
    assert.deepStrictEqual(
      formatOutputId(expectedOutPoint),
      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00:0'
    );
    assert.deepStrictEqual(parseOutputId(formatOutputId(expectedOutPoint)), expectedOutPoint);
  });

  it('identifies wallet unspents', function () {
    const unspent: Unspent = {
      id: formatOutputId(expectedOutPoint),
      address: getWalletAddress(walletKeys, 0, 0, network),
      value: 1e8,
    };
    assert.strictEqual(isWalletUnspent(unspent), false);
    assert.strictEqual(isWalletUnspent({ ...unspent, chain: 0, index: 0 } as Unspent), true);
  });

  describe('unspentSum', function () {
    const unspents = [
      mockWalletUnspent(network, 123, {
        keys: walletKeys,
        vout: 0,
      }),
      mockWalletUnspent(network, 98765, {
        keys: walletKeys,
        vout: 1,
      }),
    ];
    const bigUnspents = [
      mockWalletUnspent(network, Number.MAX_SAFE_INTEGER, {
        keys: walletKeys,
        vout: 1,
      }),
    ];
    const unspentsBig = [
      mockWalletUnspent(network, BigInt(123), {
        keys: walletKeys,
        vout: 0,
      }),
      mockWalletUnspent(network, BigInt(98765), {
        keys: walletKeys,
        vout: 1,
      }),
    ];
    it('sums number', function () {
      assert.strictEqual(unspentSum(unspents, 'number'), 123 + 98765);
    });
    it('sums bigint', function () {
      assert.strictEqual(unspentSum(unspentsBig, 'bigint'), BigInt(123 + 98765));
    });
    it('sums zero', function () {
      assert.strictEqual(unspentSum([], 'number'), 0);
      assert.strictEqual(unspentSum([], 'number'), 0);
    });
    it('throws on mixing number and bigint', function () {
      assert.throws(() => {
        unspentSum((unspentsBig as unknown as Unspent<number>[]).concat(unspents), 'number');
      });
      assert.throws(() => {
        unspentSum((unspents as unknown as Unspent<bigint>[]).concat(unspentsBig), 'bigint');
      });
    });
    it('throws on unsafe integer number', function () {
      assert.throws(() => {
        unspentSum(bigUnspents.concat(unspents), 'number');
      });
    });
    it('throws on mismatch between unspent and amountType', function () {
      assert.throws(() => {
        unspentSum(unspents, 'bigint');
      });
      assert.throws(() => {
        unspentSum(unspentsBig, 'number');
      });
    });
  });

  function constructAndSignTransactionUsingPsbt(
    unspents: WalletUnspent<bigint>[],
    signer: KeyName,
    cosigner: KeyName,
    scriptType: outputScripts.ScriptType2Of3
  ): Transaction<bigint> {
    const psbt = createPsbtForNetwork({ network });
    const total = BigInt(unspentSum<bigint>(unspents, 'bigint'));
    addWalletOutputToPsbt(psbt, walletKeys, getInternalChainCode(scriptType), CHANGE_INDEX, total - FEE);

    unspents.forEach((u) => {
      addWalletUnspentToPsbt(psbt, u, walletKeys, signer, cosigner, network);
    });

    // TODO: Test rederiving scripts from PSBT and keys only
    psbt.signAllInputsHD(walletKeys[signer]);
    psbt.signAllInputsHD(walletKeys[cosigner]);
    assert(psbt.validateSignaturesOfAllInputs());
    psbt.finalizeAllInputs();
    // extract transaction has a return type of Transaction instead of UtxoTransaction
    const tx = psbt.extractTransaction() as UtxoTransaction<bigint>;

    const psbt2 = createPsbtFromTransaction(
      tx,
      unspents.map((u) => toPrevOutput<bigint>(u, network))
    );
    const nonWitnessUnspents = unspents.filter((u): u is WalletUnspent<bigint> & UnspentWithPrevTx =>
      isUnspentWithPrevTx(u)
    );
    const txBufs = Object.fromEntries(
      psbt2.getNonWitnessPreviousTxids().map((txid) => {
        const u = nonWitnessUnspents.find((u) => parseOutputId(u.id).txid === txid);
        if (u === undefined) throw new Error('No prevtx found');
        return [txid, u.prevTx];
      })
    );
    psbt2.addNonWitnessUtxos(txBufs);
    assert(psbt2.validateSignaturesOfAllInputs());
    return tx;
  }

  function constructAndSignTransactionUsingTransactionBuilder<TNumber extends number | bigint>(
    unspents: WalletUnspent<TNumber>[],
    signer: string,
    cosigner: string,
    amountType: 'number' | 'bigint' = 'number',
    scriptType: outputScripts.ScriptType2Of3
  ): UtxoTransaction<TNumber> {
    const txb = createTransactionBuilderForNetwork<TNumber>(network);
    const total = BigInt(unspentSum<TNumber>(unspents, amountType));
    // Kinda weird, treating entire value as change, but tests the relevant paths
    txb.addOutput(
      getWalletAddress(walletKeys, getInternalChainCode(scriptType), CHANGE_INDEX, network),
      toTNumber<TNumber>(total - FEE, amountType)
    );
    unspents.forEach((u) => {
      addToTransactionBuilder(txb, u);
    });
    [
      WalletUnspentSigner.from(walletKeys, walletKeys[signer], walletKeys[cosigner]),
      WalletUnspentSigner.from(walletKeys, walletKeys[cosigner], walletKeys[signer]),
    ].forEach((walletSigner, nSignature) => {
      unspents.forEach((u, i) => {
        signInputWithUnspent(txb, i, unspents[i], walletSigner);
      });
      const tx = nSignature === 0 ? txb.buildIncomplete() : txb.build();
      // Verify each signature for the unspent
      unspents.forEach((u, i) => {
        assert.deepStrictEqual(
          verifySignatureWithUnspent(tx, i, unspents, walletKeys),
          walletKeys.triple.map((k) => k === walletKeys[signer] || (nSignature === 1 && k === walletKeys[cosigner]))
        );
      });
    });
    return txb.build();
  }

  function runTestSignUnspent<TNumber extends number | bigint>(
    scriptType: outputScripts.ScriptType2Of3,
    signer: KeyName,
    cosigner: KeyName,
    amountType: 'number' | 'bigint' = 'number',
    testOutputAmount = toTNumber<TNumber>(defaultTestOutputAmount, amountType)
  ) {
    it(`can be signed [scriptType=${scriptType} signer=${signer} cosigner=${cosigner} amountType=${amountType}]`, function () {
      const unspents = [
        mockWalletUnspent(network, testOutputAmount, {
          keys: walletKeys,
          chain: getExternalChainCode(scriptType),
          vout: 0,
        }),
        mockWalletUnspent(network, testOutputAmount, {
          keys: walletKeys,
          chain: getInternalChainCode(scriptType),
          vout: 1,
        }),
      ];
      const txbTransaction = constructAndSignTransactionUsingTransactionBuilder(
        unspents,
        signer,
        cosigner,
        amountType,
        scriptType
      );
      if (amountType === 'bigint') {
        const psbtTransaction = constructAndSignTransactionUsingPsbt(
          unspents as WalletUnspent<bigint>[],
          signer,
          cosigner,
          scriptType
        );
        assert.deepStrictEqual(txbTransaction.toBuffer(), psbtTransaction.toBuffer());
      }
    });
  }

  outputScripts.scriptTypes2Of3.forEach((t) => {
    const keyNames: KeyName[] = ['user', 'backup', 'bitgo'];
    keyNames.forEach((signer) => {
      keyNames.forEach((cosigner) => {
        if (signer !== cosigner) {
          runTestSignUnspent(t, signer, cosigner);
          runTestSignUnspent<bigint>(t, signer, cosigner, 'bigint', BigInt('10000000000000000'));
        }
      });
    });
  });
});
