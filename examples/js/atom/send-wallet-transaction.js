/**
 * Send a transaction from a tss wallet at BitGo.
 *
 * Copyright 2023, BitGo, Inc.  All Rights Reserved.
 */
const BitGoJS = require('bitgo');
const bitgo = new BitGoJS.BitGo({ env: 'test' });

// TODO: set your access token here
// You can get this from User Settings > Developer Options > Add Access Token
const accessToken = '';

// TODO: get the wallet with this id
const id = '';

const coin = 'tatom';

const receiveAddress = '';

const walletPassphrase = '';

// Create the wallet
async function main() {
  bitgo.authenticateWithAccessToken({ accessToken });

  await bitgo.unlock({ otp: '000000', duration: 3600 });
  const wallet = await bitgo.coin(coin).wallets().get({ id });

  console.log(`Wallet label: ${wallet}`);

  const whitelistedParams = {
    intent: {
      intentType: 'payment',
      sequenceId: 'himVJSkFpFB7NeF1UN32KKxXju2',
      recipients: [
        {
          address: {
            address: receiveAddress,
          },
          amount: {
            value: '100000',
            symbol: 'tatom',
          },
        },
      ],
    },
    apiVersion: 'full',
    preview: false,
  };

  const unsignedTx = (await bitgo
    .post(bitgo.url('/wallet/' + id + '/txrequests', 2))
    .send(whitelistedParams)
    .result());

  // sign tx
  const keychains = await bitgo.coin(coin).keychains().getKeysForSigning({ wallet: wallet });
  const signedTransaction = await wallet.signTransaction({
    txPrebuild: unsignedTx,
    keychain: keychains[0],
    walletPassphrase: walletPassphrase,
    pubs: keychains.map((k) => k.pub),
    reqId: unsignedTx.txRequestId,
  });

  // submit tx
  const submittedTx = await bitgo
    .post(bitgo.url('/wallet/' + id + '/tx/send'))
    .send({ txRequestId: signedTransaction.txRequestId })
    .result();

  console.log('New Transaction:', JSON.stringify(submittedTx, null, 4));

}

main().catch((e) => console.error(e));

