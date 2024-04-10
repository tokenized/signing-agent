import Tx from '../Tx.js';
import Key from '../Key.js';
import XKey, { Bip32Hardened } from '../XKey.js';
import Hash, { sha256 } from '../Hash.js';
import { mnemonic2Seed } from '../mnemonic.js';
import { arrayBufferToHex, hexToArrayBuffer } from '../utils.js';
import Signature from '../Signature.js';
import { equal } from "node:assert/strict";
import { describe, test } from "node:test";


describe('Tx', () => {
  test('empty hash', async () => {
    const bytes = new Uint8Array(0);
    const hash = await sha256(bytes.buffer);
    const correctHash =
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    equal(arrayBufferToHex(hash.toBytes()), correctHash);
  });

  test('simple hash', async () => {
    const bytes = new Uint8Array([0x61, 0x62, 0x63]);
    const hash = await sha256(bytes.buffer);
    const correctHash =
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
    equal(arrayBufferToHex(hash.toBytes()), correctHash);
  });

  test('mnemonic to seed', async () => {
    const mnemonic =
      'certain curious final grant gossip cycle crowd cheap endorse feature story avoid code obvious reopen';
    const correctSeed =
      '6f610eedc6b238faa0277e1be710d155f0b5ab54ab4307ee30f316fb2fce4f21baefa47c142e045912fe9eaf537db3c9002637c1ddea2ae44530861383d6112b';

    const seed = await mnemonic2Seed(mnemonic);

    equal(arrayBufferToHex(seed), correctSeed);
  });

  test('tx hash', async () => {
    const buffer = hexToArrayBuffer(
      'b56d79b1a085df331c18b0bd013108ca95f067cccc832aedf2f4a4674cbd7226',
    );
    const hash = await sha256(buffer);
    const correctHash =
      '590d5cc3476e34c90e680457559f3b0b23d4406ba6946dbb1f7889d515df606d';
    equal(hash.toString(), correctHash);
  });


  test('tx serialize', async () => {
    const txs = [];
    txs.push([
      '02000000015ae2b5c7ece718c7d2898c44ac80318841586a89dbc9ad25ee552ae8f5f39d650000000000ffffffff011d760200000000001976a9145389667241a2bb9a8665a463531171e50a7f058588ac00000000',
      1,
      1,
      161309n,
    ]);
    txs.push([
      '0100000002e5a2041ebfcdb5594616fd090d1065b48dbb3bb0cf75dbc0028ba3e82404665a000000006b483045022100875980a2c82af1ccb3493cf857c3d807f182c334458749b5284e7b207d16e5f402200eaba277fdb8d15e862e488074284bde0b4adfbcfe43cdbc96db29dbd380ad334121034f31d5c213db1a2847fa1a3425e9bdc5f8104d11f74b68434d8365f17acfb6c3ffffffff681506afb99bf4a98a1ab8082438003aee835ebcdc90b0fd5701769d42ac4ef3020000006a47304402201754f8aec11c2aab1c41df9e5717b9f88616cc9b0992f6a8c1f9b510f2d88429022040496964eacd71feaa628ae2824c251b2e098a9b8afb4b61cd4c34daae1d1cf24121034f31d5c213db1a2847fa1a3425e9bdc5f8104d11f74b68434d8365f17acfb6c3ffffffff03b30d0000000000001976a9145ca2479d4bc988bff6a5b67d6bebd24a4ef3ff3d88ac000000000000000095006a02bd000e746573742e746f6b656e697a6564041a0241314c7a0a08fffffffffffffff0100120015080c2d72f5a034c4f596260121e546f6b656e416972204672657175656e7420466c79657220506f696e7473188080d488b4d1a3cc1520808080eb8b91f7fc192a2a4672657175656e7420666c79657220706f696e747320666f7220546f6b656e41697220666c6967687473ce182f00000000001976a9148c9420efb9f98392397a999100a1e62cc7419ec588ac00000000',
      2,
      3,
      3507n,
    ]);
    txs.push([
      '01000000122174823f39ebe31d4f40186ed982a31e7618eb615db55bf904386b5c4c4a5917000000006b483045022100bd58b9421e90ae1ed29a217f31b4d57809b18712273ac6b1c2c822abceba985b02205a501b533969a0c1dc015cd6b7f492b1e77b08e9a97a4f61a743328581b7c34a412103d9d9ff285f49c55f4244a55ef33f2805cfdfa2cb108755e3077cca3ebf56695ffeffffff2174823f39ebe31d4f40186ed982a31e7618eb615db55bf904386b5c4c4a5917010000006a4730440220587c07901c43c4ee5f894956a4760ac8dca53a18dd015b581a7f88ae9a34200d02204ae50b55c14507eddce16cf7a2209f4fc12f4bb70e5cba265867fc7fd417b73d412102c4a15f059f901ec103ef584d4224a5cd51026a21e055031236fd30960714d25ffeffffff3476823dcd059db41e082ec9385805e7e9e646bbc6e34de348bd10c47dbea820000000006a473044022038f0ed3785fbfad659af091bdace8b4ffa573343a1794479daffb3d3fdb95a60022030aaa69f381f03c5239d4d060b40f526e1e53387c72e6696b2df6746579146df4121028be5180e3d1534709b83efc1ce82aa297ed7fbaa021389dcbd1de8d73bca5557feffffff4ed75b898a7fd8da9677a4ac1969e295dfed20a7c34f7c15b9419110722b272b020000006a47304402202ae2fa5a914b7a1d3ce8f21651b9188c9c4acae9fe95385a3f34b1f1499891970220713938d19fe936b36a941a4247c826ed910b4229b65551aba5f5bcaa759ccb50412103583440475cccfa479479c44234cf656c7468d92675c16d791ac56d24019be63efeffffff514f87f5b594880575c8d170f0e60383d94849b86d92a5e39d7cf4c2bf823b35000000006a47304402201f392b162e1d8bea8d2237fdeec56c2adce1091775dcd175f48907f97d04071c02202918444da4c63c1ca2f3a80376c3fb80ee45078c9f704949dba3dc219515eaf4412103583440475cccfa479479c44234cf656c7468d92675c16d791ac56d24019be63efeffffff514f87f5b594880575c8d170f0e60383d94849b86d92a5e39d7cf4c2bf823b35010000006a47304402205ee98819c793e568c9e1a1e02ab66fa28547fbd9b7e947949bb7d203572aa207022035d7b9c4ab5d7e278d4728bd86cd43965269569bd2812fa3944f9ea47bd4313f41210265f0ece35a4da512396fc52a979828aec581ad765615b06d0c65497ebacc8163feffffff514f87f5b594880575c8d170f0e60383d94849b86d92a5e39d7cf4c2bf823b35020000006a473044022032812093c3ee99b2cd72f5ca9524e088bf901b2c1294d6d52143be32b65b82f60220498f31dd38cdc2ada69c9eef3f7996e1607a6bcdc89418b71cec6e5bf1ab96ab412103582881a1c1a7a2c005928686afe8a4a2a08b42370f602c3467fff8d75d7dde96feffffff514f87f5b594880575c8d170f0e60383d94849b86d92a5e39d7cf4c2bf823b35030000006b483045022100df785d8a062cd3c7561b38fb1bff4c183b9cc763dfb753d27fc0d49e6ebdbfcf02203e062b428b234c0cea89cb7370b33e7854c36a5302244149de50d001b0f4b9f5412102c4a15f059f901ec103ef584d4224a5cd51026a21e055031236fd30960714d25ffeffffff514f87f5b594880575c8d170f0e60383d94849b86d92a5e39d7cf4c2bf823b35050000006b4830450221008c3e45a357c5cc195fca02fe1c7fca6ab22d26749195959c12a3def3eae8d3c802205a91ff3562d5221fc6eec69ac84fcb89a3ac9b5dd7e09bf8e32913c056168e9c412103d9d9ff285f49c55f4244a55ef33f2805cfdfa2cb108755e3077cca3ebf56695ffeffffffcec83b16046cc66f5c1927ae4b928351089cbb947c4486b3a0af58e29e0de346000000006b483045022100ae646d9c00892a931cbf92ea410a10ad26a08755ade36c5d3dbc0d886bbc198302207333c0f8cdfe65f3db6a1defc81aa1c187c0684188341adc1e9de1a9642a188a412103d9d9ff285f49c55f4244a55ef33f2805cfdfa2cb108755e3077cca3ebf56695ffeffffffcec83b16046cc66f5c1927ae4b928351089cbb947c4486b3a0af58e29e0de346010000006b483045022100ba4cc782a523d2e4f0c074494a14b035167de856009432f3fee89ec6b6b7fdbc02205d4e60682301ab6cb5ec49bc92443b44ea7d87de65c888f26901c1554132b437412102c4a15f059f901ec103ef584d4224a5cd51026a21e055031236fd30960714d25ffeffffff4ec189026c2591a243132b974e5fbca12eea17fbf2b81f7ca3d6d14bb26cf668000000006b483045022100d01ae3410d2ce839ec88d72632842901f71c85bd3a78e850bb14a6fcb30ac9ce02207e47baef767e224faf7985b6f44183196fa3a44c6eeac6867411f2aa36352ac6412103d9d9ff285f49c55f4244a55ef33f2805cfdfa2cb108755e3077cca3ebf56695ffeffffff4ec189026c2591a243132b974e5fbca12eea17fbf2b81f7ca3d6d14bb26cf668010000006b483045022100959bd55ffe2f7af9d60e15f5fcb4fbd6abd1c6409455df78fb551a9f6695d74e022005a5c953e4e84d77b9becbd90e1773e70ebfaa4d2f05f63e17531f39c7ba5341412102c4a15f059f901ec103ef584d4224a5cd51026a21e055031236fd30960714d25ffeffffff2d5bfd4913e070c91a819343d9b35fd9afe1dbd2ec59cb1b854c5ceeecfce56b000000006b483045022100a2e03a9684223a23768f38394caeeb76b26e3fcb6ed850be92fbc27c2d1b1f2002201bb5ff7f380c72bf8cf06c8852061a80f3e4296267ca9b461eafb9db9871e18a412103d9d9ff285f49c55f4244a55ef33f2805cfdfa2cb108755e3077cca3ebf56695ffeffffff2d5bfd4913e070c91a819343d9b35fd9afe1dbd2ec59cb1b854c5ceeecfce56b010000006a473044022015b4e36f5a8d64e01965c0e3e7711c8bf14b14b5285d76d4c25add20f41e52c902205855e43260774dbd9617dfdfe0fd7b8a7a3b054f8dc074f2bad7cb3f0450f0c2412102c4a15f059f901ec103ef584d4224a5cd51026a21e055031236fd30960714d25ffeffffffd20750180e53d71ea1994763cee2131d2536fefe5865534c12d311838814cb81000000006b483045022100e16240c1e66b9e407d16c96d165fd84fd49a9dc4a0f8681492aa22921c8fe6fc0220169cf13c4b583ba9dda3ec996001d3b63c8b4e91e6a93389c5c35b07f70c69ba412103d9d9ff285f49c55f4244a55ef33f2805cfdfa2cb108755e3077cca3ebf56695ffeffffffd20750180e53d71ea1994763cee2131d2536fefe5865534c12d311838814cb81010000006b483045022100c92c117ea32df882444b314d6be8e16a665fc816549aa46fb984a65cf06d04770220430eac5496a1409e0c2e029504e948f68be8b17123bd25008e9f8c44fbdd3acb412102c4a15f059f901ec103ef584d4224a5cd51026a21e055031236fd30960714d25ffeffffffc58ff68f6cd7bdc52c720f48a414e29f2fb65cd0730b56b3f48259f7081421d4020000006a4730440220639956eae85d7d55c8996be39f37ba1189059974b790c4c2af29cd3ce67c05360220588e19bc4e6f50304d6a31de7e874ba6fc16c2fbc42d204499e7835d6d143dd3412102c4a15f059f901ec103ef584d4224a5cd51026a21e055031236fd30960714d25ffeffffff01315a2f00000000001976a9148c9420efb9f98392397a999100a1e62cc7419ec588ac6ae30800',
      18,
      1,
      3103281n,
    ]);

    let i;
    for (i = 0; i < txs.length; i += 1) {
      const tx = new Tx(txs[i][0]);

      // console.log("Read Tx : " + tx.id('hex'));
      // console.log(tx);

      const written = tx.toString();
      equal(written, txs[i][0]);

      equal(tx.inputs.length, txs[i][1]);
      equal(tx.outputs.length, txs[i][2]);
      equal(tx.outputs[0].value, txs[i][3]);
    }

    const signedTxData =
      '0100000002e5a2041ebfcdb5594616fd090d1065b48dbb3bb0cf75dbc0028ba3e82404665a000000006b483045022100875980a2c82af1ccb3493cf857c3d807f182c334458749b5284e7b207d16e5f402200eaba277fdb8d15e862e488074284bde0b4adfbcfe43cdbc96db29dbd380ad334121034f31d5c213db1a2847fa1a3425e9bdc5f8104d11f74b68434d8365f17acfb6c3ffffffff681506afb99bf4a98a1ab8082438003aee835ebcdc90b0fd5701769d42ac4ef3020000006a47304402201754f8aec11c2aab1c41df9e5717b9f88616cc9b0992f6a8c1f9b510f2d88429022040496964eacd71feaa628ae2824c251b2e098a9b8afb4b61cd4c34daae1d1cf24121034f31d5c213db1a2847fa1a3425e9bdc5f8104d11f74b68434d8365f17acfb6c3ffffffff03b30d0000000000001976a9145ca2479d4bc988bff6a5b67d6bebd24a4ef3ff3d88ac000000000000000095006a02bd000e746573742e746f6b656e697a6564041a0241314c7a0a08fffffffffffffff0100120015080c2d72f5a034c4f596260121e546f6b656e416972204672657175656e7420466c79657220506f696e7473188080d488b4d1a3cc1520808080eb8b91f7fc192a2a4672657175656e7420666c79657220706f696e747320666f7220546f6b656e41697220666c6967687473ce182f00000000001976a9148c9420efb9f98392397a999100a1e62cc7419ec588ac00000000';

    const tx = new Tx(signedTxData);
    equal(tx.toString(), signedTxData);

    // first hash b56d79b1a085df331c18b0bd013108ca95f067cccc832aedf2f4a4674cbd7226

    const txid = await tx.id('hex');
    equal(txid, 
      '590d5cc3476e34c90e680457559f3b0b23d4406ba6946dbb1f7889d515df606d',
    );

    const sigHash1 = await tx.sigHash(
      0,
      Buffer.alloc(
        25,
        '76a9148c9420efb9f98392397a999100a1e62cc7419ec588ac',
        'hex',
      ),
      3294,
    );
    // console.log('Sig Hash: ' + sigHash1.toString('hex'))
    equal(sigHash1.toString('hex'), 
      '81f3ea796811a2d58007c5dec1d325c995a58fc2626e3acb87e126515c8b6354',
    );
  });

  // xkey mnemonic : drift basic fame sight capital seven spot win humble regret alpha shift custom click galaxy
  // xkey seed : 371c6987141e30d3a2d7fa35c19bf476bdce121db0f7ed10248b36708a3d3a71f9c5ef71d1efb31f55567c2a3bc6d8a134212229f05bb0a88828368022468e87

  test('xkey (bip32) root', () => {
    const xkey = new XKey(
      'xprv9s21ZrQH143K3hJk1gVbS5EdekArYf5Rk1xKRDkkZAbpDEaFzWQkfvPEthzgKGsUtoTRV14LZVh4pam8WckasA71ZLWN1MkPf1Sw794kTcw',
    );
    equal(xkey.isPrivate(), true);
  });

  test('xkey (bip32) child m/5', () => {
    const xkey = new XKey(
      'xprv9vDE3qgGTP5sDGjTCKBtF46Gf4iBwxbcBmobLakz1yKgMspoVYqKXixTJP2GuSJ1M7uxUD8KWkiFdEvupbqbd1GXGS68Sc6xFQE82viz9H9',
    );
    equal(xkey.isPrivate(), true);
    equal(xkey.index, 5);
  });

  test("xkey (bip32) child m/5/2'", async () => {
    const xkey = new XKey(
      'xprv9w1T359ct1N4vQivGTF2o72r5iKpg9CmCujTcSyGbfMQp341iEja8cn8Xa45o5qdMQscXMxwf4WMzzTXNSqqgKHCmQL2WYCpVRqGkiH2iLn',
    );
    equal(xkey.isPrivate(), true);
    equal(xkey.index, 2 + Bip32Hardened);

    // child 1
    // address 1SBiXiC3exDRhZXi3pX7oyKqAZAV4aZex
    // public 03b2087cc4be2c8d103b8122247bd557f3cb76ba2f7ed0279d0246362b03016303
    // private KzKitEMxyBKwY2pXxVjNCxMokjWMWXydSgVBaW53fma6RLzRgc4s
    const child = await xkey.derive('m/1');
    equal(child.toString(), 
      'xprv9xh5e7ijHEoDKmqasgHisgsoqhSrCg1nCkWvJsEdkqnrNcmvsaTjqyJKiSWc8ru7tzmJNh3AKQHvdYGdDnrzqVfJqRTWueD8NQdVV5aE1vu',
    );

    equal(child.key().toString(), 
      'KzKitEMxyBKwY2pXxVjNCxMokjWMWXydSgVBaW53fma6RLzRgc4s',
    );

    equal(child.publicKey().toString(), 
      '03b2087cc4be2c8d103b8122247bd557f3cb76ba2f7ed0279d0246362b03016303',
    );

    const hardChild = await child.derive("m/1'");
    equal(hardChild.toString(), 
      'xprv9zaamjzwnqe4eapXZaLqLfRbEGgkUNh2eNy69ZUb5oU29vZcRzUagwNd1ZcGYYDZVcp4ZxTenNAR3fYfC2QCG4dP38mbLrUEV1xvWfUUjwY',
    );
  });

  test('xkey (bip32) to public', () => {
    const xkey = new XKey(
      'xprv9w1T359ct1N75AHd9PPAfjG1eBrcP7UkdFEZYakrhUiss6ToH2SWUUwAB8SbkLZDAXFbtoy7ybssUqsiEFrDutvNuepUiHnfZtNNX55HcbC',
    );
    const xpub = xkey.toPublic();

    equal(xpub.toString(), 
      'xpub69zoSagWiNvQHeN6FQvB2sCkCDh6naCbzUAALyAUFpFrjtnwpZkm2HFe2PuVVHbccDDifg5PzCMhNXA2FRz464tbbksXLhwaaegpXvdWX4e',
    );
  });

  test('xkey (bip32) from seed', async () => {
    const buf = Buffer.from(
      '371c6987141e30d3a2d7fa35c19bf476bdce121db0f7ed10248b36708a3d3a71f9c5ef71d1efb31f55567c2a3bc6d8a134212229f05bb0a88828368022468e87',
      'hex',
    );

    const xkey = await XKey.fromSeed(buf);
    equal(xkey.toString(), 
      'xprv9s21ZrQH143K3hJk1gVbS5EdekArYf5Rk1xKRDkkZAbpDEaFzWQkfvPEthzgKGsUtoTRV14LZVh4pam8WckasA71ZLWN1MkPf1Sw794kTcw',
    );
  });
});
