const aptos = require('aptos');

const NODE_URL = process.env.APTOS_NODE_URL || 'https://fullnode.devnet.aptoslabs.com';
const FAUCET_URL = process.env.APTOS_FAUCET_URL || 'https://faucet.devnet.aptoslabs.com';

(async () => {
  const client = new aptos.AptosClient(NODE_URL);
  const faucetClient = new aptos.FaucetClient(NODE_URL, FAUCET_URL, null);

  const account1 = new aptos.AptosAccount();
  await faucetClient.fundAccount(account1.address(), 5000);
  let resources = await client.getAccountResources(account1.address());
  let accountResource = resources.find((r) => r.type === '0x1::Coin::CoinStore<0x1::TestCoin::TestCoin>');
  console.log(`account2 coins: ${accountResource.data.coin.value}. Should be 5000!`);

  const account2 = new aptos.AptosAccount();
  await faucetClient.fundAccount(account2.address(), 0);
  resources = await client.getAccountResources(account2.address());
  accountResource = resources.find((r) => r.type === '0x1::Coin::CoinStore<0x1::TestCoin::TestCoin>');
  console.log(`account2 coins: ${accountResource.data.coin.value}. Should be 0!`);

  const payload = {
    type: 'script_function_payload',
    function: '0x1::Coin::transfer',
    type_arguments: ['0x1::TestCoin::TestCoin'],
    arguments: [account2.address().hex(), '717'],
  };
  const txnRequest = await client.generateTransaction(account1.address(), payload);
  const signedTxn = await client.signTransaction(account1, txnRequest);
  const transactionRes = await client.submitTransaction(signedTxn);
  await client.waitForTransaction(transactionRes.hash);

  resources = await client.getAccountResources(account2.address());
  accountResource = resources.find((r) => r.type === '0x1::Coin::CoinStore<0x1::TestCoin::TestCoin>');
  console.log(`account2 coins: ${accountResource.data.coin.value}. Should be 717!`);
})();
