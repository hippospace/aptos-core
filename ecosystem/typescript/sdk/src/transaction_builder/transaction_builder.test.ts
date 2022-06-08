/* eslint-disable max-len */
import * as Nacl from 'tweetnacl';
import { bcsSerializeUint64, bcsToBytes, Bytes } from './bcs';
import { HexString } from '../hex_string';

import { TransactionBuilderEd25519 } from './index';
import {
  AccountAddress,
  ChainId,
  Ed25519Signature,
  Module,
  ModuleBundle,
  RawTransaction,
  Script,
  ScriptFunction,
  StructTag,
  TransactionArgumentAddress,
  TransactionArgumentU8,
  TransactionArgumentU8Vector,
  TransactionPayloadModuleBundle,
  TransactionPayloadScript,
  TransactionPayloadScriptFunction,
  TypeTagStruct,
} from './aptos_types';

const ADDRESS_1 = '0x1222';
const ADDRESS_2 = '0xdd';
const ADDRESS_3 = '0x0a550c18';
const ADDRESS_4 = '0x01';
const PRIVATE_KEY = '9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f';
const TXN_EXPIRE = '18446744073709551615';

function hexToBytes(hex: string) {
  return new HexString(hex).toUint8Array();
}

function hexSignedTxn(signedTxn: Uint8Array): string {
  return Buffer.from(signedTxn).toString('hex');
}

function sign(rawTxn: RawTransaction): Bytes {
  const privateKeyBytes = new HexString(PRIVATE_KEY).toUint8Array();
  const signingKey = Nacl.sign.keyPair.fromSeed(privateKeyBytes.slice(0, 32));
  const { publicKey } = signingKey;

  const txnBuilder = new TransactionBuilderEd25519(
    (signingMessage) => new Ed25519Signature(Nacl.sign(signingMessage, signingKey.secretKey).slice(0, 64)),
    publicKey,
  );

  return txnBuilder.sign(rawTxn);
}

test('serialize script function payload with no type args', () => {
  const scriptFunctionPayload = new TransactionPayloadScriptFunction(
    ScriptFunction.natual(
      `${ADDRESS_1}::TestCoin`,
      'transfer',
      [],
      [bcsToBytes(AccountAddress.fromHex(ADDRESS_2)), bcsSerializeUint64(1)],
    ),
  );

  const rawTxn = new RawTransaction(
    AccountAddress.fromHex(new HexString(ADDRESS_3)),
    0n,
    scriptFunctionPayload,
    2000n,
    0n,
    BigInt(TXN_EXPIRE),
    false,
    new ChainId(4),
  );

  const signedTxn = sign(rawTxn);

  expect(hexSignedTxn(signedTxn)).toBe(
    '000000000000000000000000000000000000000000000000000000000a550c1800000000000000000300000000000000000000000000000000000000000000000000000000000012220854657374436f696e087472616e7366657200022000000000000000000000000000000000000000000000000000000000000000dd080100000000000000d0070000000000000000000000000000ffffffffffffffff00040020b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a4920040282faeda6a67d7c819514627c0e6124e9c71d048c8204534d4e14bfd463a541961e270c5e06c8afc0211e7356f1697192182ebb6e22a4efba052f160eafaf108',
  );
});

test('serialize script function payload with type args', () => {
  const token = new TypeTagStruct(StructTag.fromString(`${ADDRESS_4}::TestCoin::TestCoin`));

  const scriptFunctionPayload = new TransactionPayloadScriptFunction(
    ScriptFunction.natual(
      `${ADDRESS_1}::Coin`,
      'transfer',
      [token],
      [bcsToBytes(AccountAddress.fromHex(ADDRESS_2)), bcsSerializeUint64(1)],
    ),
  );

  const rawTxn = new RawTransaction(
    AccountAddress.fromHex(ADDRESS_3),
    0n,
    scriptFunctionPayload,
    2000n,
    0n,
    BigInt(TXN_EXPIRE),
    false,
    new ChainId(4),
  );

  const signedTxn = sign(rawTxn);

  expect(hexSignedTxn(signedTxn)).toBe(
    '000000000000000000000000000000000000000000000000000000000a550c18000000000000000003000000000000000000000000000000000000000000000000000000000000122204436f696e087472616e73666572010700000000000000000000000000000000000000000000000000000000000000010854657374436f696e0854657374436f696e00022000000000000000000000000000000000000000000000000000000000000000dd080100000000000000d0070000000000000000000000000000ffffffffffffffff00040020b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a4920040b6fc1af14d490469c0deccb8976aace7bdfd28e67ee1d4b34bd60fa1c9462d18ea5e7f90b2cc65743934d162a96f70ffe2c4d11990cf036fd5bd98dbdd0fd709',
  );
});

test('serialize script function payload with type args but no function args', () => {
  const token = new TypeTagStruct(StructTag.fromString(`${ADDRESS_4}::TestCoin::TestCoin`));

  const scriptFunctionPayload = new TransactionPayloadScriptFunction(
    ScriptFunction.natual(`${ADDRESS_1}::Coin`, 'fake_func', [token], []),
  );

  const rawTxn = new RawTransaction(
    AccountAddress.fromHex(ADDRESS_3),
    0n,
    scriptFunctionPayload,
    2000n,
    0n,
    BigInt(TXN_EXPIRE),
    false,
    new ChainId(4),
  );

  const signedTxn = sign(rawTxn);

  expect(hexSignedTxn(signedTxn)).toBe(
    '000000000000000000000000000000000000000000000000000000000a550c18000000000000000003000000000000000000000000000000000000000000000000000000000000122204436f696e0966616b655f66756e63010700000000000000000000000000000000000000000000000000000000000000010854657374436f696e0854657374436f696e0000d0070000000000000000000000000000ffffffffffffffff00040020b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a492004012f0e61b4fdf7ef33ed44818627b9589f1e8b87bb1b843cfa62048aa60fc5ca985c88798f3d65cbe763277f5a575081821a64e3149fc898d75bc8a0a8a91ca06',
  );
});

test('serialize script payload with no type args and no function args', () => {
  const script = hexToBytes('a11ceb0b030000000105000100000000050601000000000000000600000000000000001a0102');

  const scriptPayload = new TransactionPayloadScript(new Script(script, [], []));

  const rawTxn = new RawTransaction(
    AccountAddress.fromHex(ADDRESS_3),
    0n,
    scriptPayload,
    2000n,
    0n,
    BigInt(TXN_EXPIRE),
    false,
    new ChainId(4),
  );

  const signedTxn = sign(rawTxn);

  expect(hexSignedTxn(signedTxn)).toBe(
    '000000000000000000000000000000000000000000000000000000000a550c1800000000000000000126a11ceb0b030000000105000100000000050601000000000000000600000000000000001a01020000d0070000000000000000000000000000ffffffffffffffff00040020b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a4920040e4d8723f252b0a89cacf73467cac8ac6a5f6fbfb68bf780a9e0a923404a2a930867d7f8f91da88d7463ba8eba1946cb03df61e81fc47872af91624b793838902',
  );
});

test('serialize script payload with type args but no function args', () => {
  const token = new TypeTagStruct(StructTag.fromString(`${ADDRESS_4}::TestCoin::TestCoin`));

  const script = hexToBytes('a11ceb0b030000000105000100000000050601000000000000000600000000000000001a0102');

  const scriptPayload = new TransactionPayloadScript(new Script(script, [token], []));

  const rawTxn = new RawTransaction(
    AccountAddress.fromHex(ADDRESS_3),
    0n,
    scriptPayload,
    2000n,
    0n,
    BigInt(TXN_EXPIRE),
    false,
    new ChainId(4),
  );

  const signedTxn = sign(rawTxn);

  expect(hexSignedTxn(signedTxn)).toBe(
    '000000000000000000000000000000000000000000000000000000000a550c1800000000000000000126a11ceb0b030000000105000100000000050601000000000000000600000000000000001a0102010700000000000000000000000000000000000000000000000000000000000000010854657374436f696e0854657374436f696e0000d0070000000000000000000000000000ffffffffffffffff00040020b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a4920040a3d4ba4f7f3cf86536e6b58bfaa4de19b02a4ca3ae92019e0e39599d068feb88d54d7325176065cda2792e548d6f8f4fcf475472f7931864cf96177916d04201',
  );
});

test('serialize script payload with one type arg and one function arg', () => {
  const token = new TypeTagStruct(StructTag.fromString(`${ADDRESS_4}::TestCoin::TestCoin`));

  const argU8 = new TransactionArgumentU8(2);

  const script = hexToBytes('a11ceb0b030000000105000100000000050601000000000000000600000000000000001a0102');

  const scriptPayload = new TransactionPayloadScript(new Script(script, [token], [argU8]));
  const rawTxn = new RawTransaction(
    AccountAddress.fromHex(ADDRESS_3),
    0n,
    scriptPayload,
    2000n,
    0n,
    BigInt(TXN_EXPIRE),
    false,
    new ChainId(4),
  );

  const signedTxn = sign(rawTxn);

  expect(hexSignedTxn(signedTxn)).toBe(
    '000000000000000000000000000000000000000000000000000000000a550c1800000000000000000126a11ceb0b030000000105000100000000050601000000000000000600000000000000001a0102010700000000000000000000000000000000000000000000000000000000000000010854657374436f696e0854657374436f696e00010002d0070000000000000000000000000000ffffffffffffffff00040020b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a4920040cbbbcebff26a35590c36066003e0660cbb458377e3d37a2b5316ae1952df64eba88e3287f34cd547f47bfaf18e9e196791600c504bd555a55e830885e1469607',
  );
});

test('serialize script payload with one type arg and two function args', () => {
  const token = new TypeTagStruct(StructTag.fromString(`${ADDRESS_4}::TestCoin::TestCoin`));

  const argU8Vec = new TransactionArgumentU8Vector(bcsSerializeUint64(1));
  const argAddress = new TransactionArgumentAddress(AccountAddress.fromHex('0x01'));

  const script = hexToBytes('a11ceb0b030000000105000100000000050601000000000000000600000000000000001a0102');

  const scriptPayload = new TransactionPayloadScript(new Script(script, [token], [argU8Vec, argAddress]));

  const rawTxn = new RawTransaction(
    AccountAddress.fromHex(ADDRESS_3),
    0n,
    scriptPayload,
    2000n,
    0n,
    BigInt(TXN_EXPIRE),
    false,
    new ChainId(4),
  );

  const signedTxn = sign(rawTxn);

  expect(hexSignedTxn(signedTxn)).toBe(
    '000000000000000000000000000000000000000000000000000000000a550c1800000000000000000126a11ceb0b030000000105000100000000050601000000000000000600000000000000001a0102010700000000000000000000000000000000000000000000000000000000000000010854657374436f696e0854657374436f696e000204080100000000000000030000000000000000000000000000000000000000000000000000000000000001d0070000000000000000000000000000ffffffffffffffff00040020b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a4920040a6c5cff36d3af6f46fae5e553717648e41b99719744e902f57229ef16ed70c7e008c1ee6d5eb3ab24ad010aebc6884037f03cb09323b54cba58b327f68d95303',
  );
});

test('serialize module payload', () => {
  const module = hexToBytes(
    'a11ceb0b0300000006010002030205050703070a0c0816100c260900000001000100000102084d794d6f64756c650269640000000000000000000000000b1e55ed00010000000231010200',
  );

  const modulePayload = new TransactionPayloadModuleBundle(new ModuleBundle([new Module(module)]));

  const rawTxn = new RawTransaction(
    AccountAddress.fromHex(ADDRESS_3),
    0n,
    modulePayload,
    2000n,
    0n,
    BigInt(TXN_EXPIRE),
    false,
    new ChainId(4),
  );

  const signedTxn = sign(rawTxn);

  expect(hexSignedTxn(signedTxn)).toBe(
    '000000000000000000000000000000000000000000000000000000000a550c18000000000000000002014ba11ceb0b0300000006010002030205050703070a0c0816100c260900000001000100000102084d794d6f64756c650269640000000000000000000000000b1e55ed00010000000231010200d0070000000000000000000000000000ffffffffffffffff00040020b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a4920040c6433098735f1fe1e5492fbf1da2ffcbd771e9a8da0277cd8d94b92dfdd3b824fcaea99f6685387289bdc4b666b8d31ad552c945a8d4f1657e29f0b83e56da01',
  );
});
