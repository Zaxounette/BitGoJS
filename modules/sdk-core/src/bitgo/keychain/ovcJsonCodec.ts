/* eslint-disable no-redeclare */
import * as t from 'io-ts';

export const OvcShare = t.type(
  {
    publicShare: t.string,
    privateShare: t.string,
    vssProof: t.string,
    i: t.number,
    j: t.number,
  },
  'OvcShare'
);

export const OvcToOtherShare = t.intersection(
  [
    OvcShare,
    t.type({
      uSig: t.string,
    }),
  ],
  'OvcToOtherShare'
);

export const OvcToBitGoJSON = t.strict(
  {
    tssVersion: t.string,
    walletType: t.string,
    coin: t.string,
    state: t.number,
    ovc: t.type({
      1: t.type({
        gpgPubKey: t.string,
        ovcToBitgoShare: OvcToOtherShare,
      }),
      2: t.type({
        gpgPubKey: t.string,
        ovcToBitgoShare: OvcToOtherShare,
        ovcToOvcShare: OvcToOtherShare,
      }),
    }),
  },
  'OvcToBitGoJSON'
);

export type OvcToBitGoJSON = t.TypeOf<typeof OvcToBitGoJSON>;

export const BitGoToOvcJSON = t.intersection(
  [
    OvcToBitGoJSON,
    t.type({
      platform: t.type({
        commonKeychain: t.string,
        walletHSMGPGPublicKeySigs: t.string,
        ovc: t.type({
          // BitGo to User (OVC-1)
          1: t.type({
            bitgoToOvcShare: OvcShare,
          }),
          // BitGo to Backup (OVC-2)
          2: t.type({
            bitgoToOvcShare: OvcShare,
          }),
        }),
      }),
    }),
  ],
  'BitgoToOvcJson'
);

export const BitGoKeyFromOvcShares = t.strict(
  {
    bitGoOutputJsonForOvc: BitGoToOvcJSON,
    bitGoKeyId: t.string,
  },
  'BitGoKeyFromOvcShares'
);

export type BitGoKeyFromOvcShares = t.TypeOf<typeof BitGoKeyFromOvcShares>;
