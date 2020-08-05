import { KeyPair } from '../../../src/coin/hbar/keyPair';

export const ACCOUNT_1 = {
  accountId: '0.0.81320',
  publicKey: '302a300506032b65700321005a9111b5e6881ff20b9243a42ac1a9a67fa16cd4f01e58bab30c1fe611ea8cf9',
  privateKey: '302e020100300506032b65700422042062b0b669de0ab5e91b4328e1431859a5ca47e7426e701019272f5c2d52825b01',
};

export const ACCOUNT1 = '0.0.75861';

export const OPERATOR = {
  accountId: '0.0.75861',
  publicKey: '302a300506032b6570032100d32b7b1eb103c10a6c8f6ec575b8002816e9725d95485b3d5509aa8c89b4528b',
  privateKey: '302e020100300506032b65700422042088b5af9484cef4b0aab6e0ba1002313fdfdfacfdf23d6d0957dc5f2c24fc3b81',
};

export const OWNER1 = '1c5b8332673e2bdd7d677970e549e05157ea6a94f41a5da5020903c1c391f8ef';

export const OWNER2 = '265f7cc91c0330ef27a626ff8688da761ab0543d33ba63c8315e2c91b6c595af';

export const OWNER3 = '03ad12643db2a6ba5cf8a1da14d4bd5ee46625f88886d01cc70d2d9c6ee22666';

export const FEE = '1000000000';

export const VALID_ADDRESS = { address: '10.0.24141' };

export const INVALID_ADDRESS = { address: '1002.4141' };

export const TX_JSON = 'not defined';

export const SERIALIZED = 'not defined';

export const WALLET_INITIALIZATION =
  '229f010a100a080888e1e0f8051000120418d5d00412021804188094ebdc03220208785a7d0a722a700802126c0a2212201c5b8332673e2bdd7d677970e549e05157ea6a94f41a5da5020903c1c391f8ef0a221220265f7cc91c0330ef27a626ff8688da761ab0543d33ba63c8315e2c91b6c595af0a22122003ad12643db2a6ba5cf8a1da14d4bd5ee46625f88886d01cc70d2d9c6ee2266610004a0508d0c8e103';

export const sourcePrv =
  '0a410c8fe4912e3652b61dd222b1b4d7773261537d7ebad59df6cd33622a693e0a410c8fe4912e3652b61dd222b1b4d7773261537d7ebad59df6cd33622a693e';

export const PRIVATE_KEY = '422042088b5af9484cef4b0aab6e0ba1002313fdfdfacfdf23d6d0957dc5f2c24fc3b81';

export const ENCODED_TRANSACTION = 'not defined';
export const errorMessageInvalidPrivateKey = 'Invalid private key';
export const errorMessageInvalidPublicKey = 'Invalid public key:';
export const errorMessageNotPossibleToDeriveAddress = 'Address derivation is not supported in Hedera';

export const privateKeyBytes = Uint8Array.of(
  98,
  176,
  182,
  105,
  222,
  10,
  181,
  233,
  27,
  67,
  40,
  225,
  67,
  24,
  89,
  165,
  202,
  71,
  231,
  66,
  110,
  112,
  16,
  25,
  39,
  47,
  92,
  45,
  82,
  130,
  91,
  1,
);

export const publicKeyBytes = Uint8Array.of(
  90,
  145,
  17,
  181,
  230,
  136,
  31,
  242,
  11,
  146,
  67,
  164,
  42,
  193,
  169,
  166,
  127,
  161,
  108,
  212,
  240,
  30,
  88,
  186,
  179,
  12,
  31,
  230,
  17,
  234,
  140,
  249,
);

export const ed25519PrivKeyPrefix = '302e020100300506032b657004220420';
export const ed25519PubKeyPrefix = '302a300506032b6570032100';
export const errorMessageFailedToParse = 'Failed to parse correct key';

export const INVALID_KEYPAIR_PRV = new KeyPair({
  prv: '8CAA00AE63638B0542A304823D66D96FF317A576F692663DB2F85E60FAB2590C',
});

export const KEYPAIR_PRV = new KeyPair({
  prv: '302e020100300506032b65700422042062b0b669de0ab5e91b4328e1431859a5ca47e7426e701019272f5c2d52825b01',
});

export const WALLET_TXDATA = Uint8Array.from(
  Buffer.from(
    '22a3010a140a0c0883aa91f9051080feab9b01120418d5d00412021804188094ebdc03220208785a7d0a722a700802126c0a2212205a9111b5e6881ff20b9243a42ac1a9a67fa16cd4f01e58bab30c1fe611ea8cf90a221220592a4fbb7263c59d450e651df96620dc9208ee7c7d9d6f2fdcb91c53f88312610a221220fa344793601cef71348f994f30a168c2dd55f357426a180a5a724d7e03585e9110004a0508d0c8e103',
    'hex',
  ),
);
export const WALLET_SIGNED_TRANSACTION =
  '1a660a640a205a9111b5e6881ff20b9243a42ac1a9a67fa16cd4f01e58bab30c1fe611ea8cf91a40ff00c43d4da6d33abf90b2de7d36db8cea62248a6b8ef35be7741c43e762f1208fe5224ac79cd53e59df48913418e976320f789a091cf67a23278a12781b490d22a3010a140a0c0883aa91f9051080feab9b01120418d5d00412021804188094ebdc03220208785a7d0a722a700802126c0a2212205a9111b5e6881ff20b9243a42ac1a9a67fa16cd4f01e58bab30c1fe611ea8cf90a221220592a4fbb7263c59d450e651df96620dc9208ee7c7d9d6f2fdcb91c53f88312610a221220fa344793601cef71348f994f30a168c2dd55f357426a180a5a724d7e03585e9110004a0508d0c8e103';