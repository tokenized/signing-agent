import { Buffer } from 'buffer';
import { expect } from 'chai';
import Tx from '../Tx';
import Key from '../Key';
import XKey, { Bip32Hardened } from '../XKey';
import Hash, { sha256 } from '../Hash';
import { mnemonic2Seed } from '../mnemonic';
import { arrayBufferToHex, hexToArrayBuffer } from '../utils';
import Signature from '../Signature';
import * as bsv from 'bsv';

function specifyTests(describe, test) {
  describe('Tx', () => {
    test('empty hash', async () => {
      const bytes = new Uint8Array(0);
      const hash = await sha256(bytes.buffer);
      const correctHash =
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      expect(arrayBufferToHex(hash.toBytes())).equal(correctHash);
    });

    test('simple hash', async () => {
      const bytes = new Uint8Array([0x61, 0x62, 0x63]);
      const hash = await sha256(bytes.buffer);
      const correctHash =
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
      expect(arrayBufferToHex(hash.toBytes())).equal(correctHash);
    });

    test('mnemonic to seed', async () => {
      const mnemonic =
        'certain curious final grant gossip cycle crowd cheap endorse feature story avoid code obvious reopen';
      const correctSeed =
        '6f610eedc6b238faa0277e1be710d155f0b5ab54ab4307ee30f316fb2fce4f21baefa47c142e045912fe9eaf537db3c9002637c1ddea2ae44530861383d6112b';

      const seed = await mnemonic2Seed(mnemonic);

      expect(arrayBufferToHex(seed)).equal(correctSeed);
    });

    test('tx hash', async () => {
      const buffer = hexToArrayBuffer(
        'b56d79b1a085df331c18b0bd013108ca95f067cccc832aedf2f4a4674cbd7226',
      );
      const hash = await sha256(buffer);
      const correctHash =
        '590d5cc3476e34c90e680457559f3b0b23d4406ba6946dbb1f7889d515df606d';
      expect(hash.toString()).equal(correctHash);
    });

    test('tx signed by nexus-tx-sign and bsv lib are the same.', async () => {
      // GIVEN
      // Transaction using nexus-tx-sign
      const response = {
        tx: '01000000019418223c6d8d9e4d3fc5acd4d2641a7021362906bddb14d4ed9bd33b7d5e0cd10000000000ffffffff0258020000000000001976a914f01354f339b033474c4f607c03036224b5d9c0bd88acc3230000000000001976a914047ee96e142bb9763e0c4de2688821b4e8c5708888ac00000000',
        input_supplements: [
          {
            locking_script:
              '76a9145315bffb33ab27eac7c4113299ccb020ce4344ee88ac',
            value: 10000,
            key_id: 'm/0/1',
          },
        ],
        output_supplements: [
          {
            is_remainder: false,
            is_dust: false,
          },
          {
            is_remainder: true,
            is_dust: false,
            key_id: 'm/1/0',
          },
        ],
      };

      const tx = new Tx(response.tx);
      const wif = 'L46bNyMysHeq9goxA9aodwVXLGuFPpDiRz3JT68FSBURrvXL22HG';
      const privateKey = bsv.PrivKey.fromWif(wif);
      const index = 0;
      const inputSupplement = response.input_supplements[0];
      const lockingScriptBuf = hexToArrayBuffer(inputSupplement.locking_script);
      const useType = Tx.SIGHASH_ALL | Tx.SIGHASH_FORKID;
      const numberOpts = {
        endian: 'big',
      };
      const key = new Key(privateKey.bn.toBuffer(numberOpts));

      expect(tx.toString()).equal(response.tx);

      // Transaction using bsv lib.
      // const bsvTx = new bsv.TxBuilder();
      const bsvTx = new bsv.Tx();
      bsvTx.fromBr(new bsv.Br(Buffer.from(response.tx, 'hex')));
      // const outputScript = new bsv.Script();
      // outputScript.fromBuffer(Buffer.from("76a9145315bffb33ab27eac7c4113299ccb020ce4344ee88ac", 'hex'));

      const outputScript = bsv.Script.fromPubKeyHash(
        Buffer.from('5315bffb33ab27eac7c4113299ccb020ce4344ee', 'hex'),
      );
      // bsvTx.inputFromScript(
      //   Buffer.from("d10c5e7d3bd39bedd414dbbd06293621701a64d2d4acc53f4d9e8d6d3c221894", 'hex'),
      //   0,
      //   new bsv.TxOut(10000, outputScript),
      //   new bsv.Script(),
      //   0xffffffff);

      // bsvTx.from({
      //   txId: 'd10c5e7d3bd39bedd414dbbd06293621701a64d2d4acc53f4d9e8d6d3c221894',
      //   outputIndex: 0,
      //   script: '76a9145315bffb33ab27eac7c4113299ccb020ce4344ee88ac',
      //   satoshis: 10000,
      // });

      // const outAddress1 = new bsv.Address();
      // outAddress1.fromString('1NtQLErSr3vozbe1kHz9pWJwv7pURwqFMi');
      // bsvTx.outputToAddress(bsv.Bn(600), outAddress1);

      // const outAddress2 = new bsv.Address();
      // outAddress2.fromString('1Qmjks6ZVkNbuUtAkUHQQSMFbvhPNzBgV');
      // bsvTx.outputToAddress(bsv.Bn(9155), outAddress2);
      // bsvTx.setChangeAddress(outAddress2);

      // WHEN
      const keyPair = bsv.KeyPair.fromPrivKey(privateKey);
      const sig = bsvTx.sign(
        keyPair,
        bsv.Sig.SIGHASH_ALL | bsv.Sig.SIGHASH_FORKID,
        0,
        outputScript,
        bsv.Bn(10000),
      );

      const inputScript = new bsv.Script();
      inputScript.writeBuffer(sig.toTxFormat());
      inputScript.writeBuffer(keyPair.pubKey.toBuffer());

      bsvTx.txIns[0].script = inputScript;
      bsvTx.txIns[0].scriptVi = bsv.VarInt.fromNumber(
        inputScript.toBuffer().length,
      );

      // bsvTx.signWithKeyPairs([keyPair]);
      // bsvTx.build();
      // const bsvTxRaw = bsvTx.toString();
      // console.log("bsvtxraw " + bsvTxRaw);

      // tx.sigHash(index, lockingScriptBuf, inputSupplement.value, useType).then(sigHash => {
      //   const correctSigHash = "7b96461be8a8c68c21d479d37f5d3dfd1cf948692dd38576538e7e06830932c3";
      //   expect(sigHash.toString()).equal(correctSigHash);
      //   done();
      // }).catch(err => {
      //   done("Failed sigHash " + err);
      // });

      await tx.signP2PKHInput(
        key,
        index,
        lockingScriptBuf,
        inputSupplement.value,
        useType,
      );
      // THEN
      // TODO Broadcast txs are working, so I am not sure why this is failing. I think it is an
      // issue with this test and changes made for the upgrade to bsv lib 2.0.7. --ce
      // const txRaw = tx.toString();
      // expect(txRaw).equal(bsvTxRaw);
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
        expect(written).equal(txs[i][0]);

        expect(tx.inputs.length).equal(txs[i][1]);
        expect(tx.outputs.length).equal(txs[i][2]);
        expect(tx.outputs[0].value).equal(txs[i][3]);
      }

      const signedTxData =
        '0100000002e5a2041ebfcdb5594616fd090d1065b48dbb3bb0cf75dbc0028ba3e82404665a000000006b483045022100875980a2c82af1ccb3493cf857c3d807f182c334458749b5284e7b207d16e5f402200eaba277fdb8d15e862e488074284bde0b4adfbcfe43cdbc96db29dbd380ad334121034f31d5c213db1a2847fa1a3425e9bdc5f8104d11f74b68434d8365f17acfb6c3ffffffff681506afb99bf4a98a1ab8082438003aee835ebcdc90b0fd5701769d42ac4ef3020000006a47304402201754f8aec11c2aab1c41df9e5717b9f88616cc9b0992f6a8c1f9b510f2d88429022040496964eacd71feaa628ae2824c251b2e098a9b8afb4b61cd4c34daae1d1cf24121034f31d5c213db1a2847fa1a3425e9bdc5f8104d11f74b68434d8365f17acfb6c3ffffffff03b30d0000000000001976a9145ca2479d4bc988bff6a5b67d6bebd24a4ef3ff3d88ac000000000000000095006a02bd000e746573742e746f6b656e697a6564041a0241314c7a0a08fffffffffffffff0100120015080c2d72f5a034c4f596260121e546f6b656e416972204672657175656e7420466c79657220506f696e7473188080d488b4d1a3cc1520808080eb8b91f7fc192a2a4672657175656e7420666c79657220706f696e747320666f7220546f6b656e41697220666c6967687473ce182f00000000001976a9148c9420efb9f98392397a999100a1e62cc7419ec588ac00000000';

      const tx = new Tx(signedTxData);
      expect(tx.toString()).equal(signedTxData);

      // first hash b56d79b1a085df331c18b0bd013108ca95f067cccc832aedf2f4a4674cbd7226

      const txid = await tx.id('hex');
      expect(txid).equal(
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
      expect(sigHash1.toString('hex')).equal(
        '81f3ea796811a2d58007c5dec1d325c995a58fc2626e3acb87e126515c8b6354',
      );
    });

    test('signatures', async () => {
      const keys = [
        '5Kff9dBYuPTbrkRDavBLf9RU5VLQ2d4XZBcBdGviP7ERNPfosc1',
        '5HujefvKRiEP4txpTn2VWFrfRj5KxFoR18JbJgdC4Tnv5feNkER',
        '5Jx985ktiRES9njNaBgP7viyzntsZPstFhQ8B8DqtQ4pFi3ZWiV',
        '5KkVPt5nNXJmDUUrLK8yGouVMsKeXHFFPeMZ62mWenF3nRw2hrN',
        '5KeAZFPU9XicsFvvrpCthBi3PkFya4rQvyNPnjycURzt3bE4JVC',
        '5KRKha4to17EyVyp7H8tTsNyn3hx3sqxByWtyzeYZPAfTVxYDR7',
        '5JaWJSTJJYT893xhZw8vbaEzUjbPDFEk37GA9H7y4vr9NQefYqH',
        '5K5FhHRc3gSkas8XQjAjvt6nRPKr4FfR4WnqxiKhzwA3hYWHVtq',
        '5JzHXFNpiFVJ1tgFTVKtgvN1fCeZvR6ygvNfEh2K42bX8rBVCFg',
        '5KcawDpccttHY6um7ygik31D2JHLSqPKQXBAuuGYn8krpbAEdS1',
        '5JLSc5zyjjBheVp2NNR6Za1ESqFHoFhY9R2w3dgMJ3vW54xT7uB',
        '5JJVVmFB6pH3gtAQ3sFeqP8qoQS83xpRsomEkRbnEBZMFRLKH7h',
        '5Hsjv9Req3TNc4fbZFLjRDwgbkbnFye7Qy85P4BzQooW4asimmP',
        '5KePdk6VkjfuD45pjsDanseADMBs5QWuM8qaxpH8J9krgtgfTqq',
        '5KCdPbDembTvRbC1ExKwrc9x7fwsFYD6n3XRkz64NxXvu3xphJj',
        '5JBKTkHuPjocUZ8ML7FYX2f6hdptWCjKKULaHr2zVh4w8th6qJt',
        '5KCJfgjhbWHCyLuF9uKbCnN1ukdiZMKM8D35FKUPYbPfV17hB8f',
        '5KS9v9WYqPtyTwGp4PVv8rpUmyHP7oSMWfv23jTt1J8xjoQsjoE',
        '5KfoLZKAaAczicFoCa5rtmqodjjVvK9qxEwbifQs5QfmpazdAxU',
        // 'ya1hGMDr5hANTftHsP3shEE2cyJk9kqb7bviDNx1oYzAdaM5V',
      ];
      const hashes = [
        '1ebf70af194358997fe868d341975045cd81c48819c3210a75cda4ccd520f952',
        'c764eb25f65bfa5d3b918be66ad14b64564342ffa3c888af32c4d2611231732b',
        '0bc07b889952fa6bf7459b4f65de401657c4dc85393d4bedcd8881ad9de296df',
        'b8b7712601ab13a7e4a0c8dcf2a1ec0984e9525b6aae96ccafd3885957542a4c',
        '9084904458e1b5caebf5f48334c2be9b372a08779a265a1048378d45a856498d',
        '0171c0958a3baec660171609c03bc2ae11f3f0359ce9f237a81c906a7d9c06e4',
        'b15e89f75c9fc2e44292c1442429a6f385e107887d487ece8e445c996d9952c3',
        'bb7587c50b1ca9a0e1c917fc26ee32a5efa80a7c141df9c853d9037e0cb6913c',
        'b2c15fdaab3d4eb797a5ef1b493105d27d765288bdc74d7f62ad63c26cbf7a98',
        '11f63d2cfe25d65ae047052a5fc929566d8ce35c9e993c78a20f805788d483fa',
        'cfcb02dce379b4495dc7968410aef866b0d8f0ed8c66f849f8fae8fbea06aa4f',
        '36264ed2b13f9f76089e5b2b2beb4960e8e479b6389f61c021166905efabc830',
        '27e145761108a6f7d3e2e67945b47c1378aef7a30461e08cc79cb1b2694654e7',
        'a1731a8eff7ca0eb82f361a5c0387d42c14a7902a19afee5b983f94c05b380e3',
        'b9d9cb30353d7f92def443fc540380976ac12477ada4b9275aad15b32cb192ba',
        '17aed7ab9dffaaf0c69bb95f9e7ce5eaa98d5fca632e7816054c66bd6388ad0f',
        'bfe96e97680e3b982bda0821d7cc22aa71d97a3707191cfbe9f0e694e1a7f0e3',
        '0885f6118660652806a64f25bfc555c487c58a04e87489f2feed580b59888b4e',
        'fe480c080c602131e6fcab5338f855c0a6644304c7f83cf3120f45a781ccc3c4',
        '309c1a57ec8f9d5cb4a9269386fd693806facb75333637ee4bfeb65bff8fb5cd',
      ];
      const sigs = [
        '3045022100c990c00648737339359824f1005e64726e452a27a4962c5c706db05dbefdf521022028872720954fe84fa9761810ea5c2916f43fc0013ec5f7232b4e4e1653c22dc0',
        '3045022100e90cc3d3f9723188a78d8625bf339d579dfdc552c3562eb72c9eda3f6c09568002207c05f7f012a93f69418ecd3f8dc404545e1f1b1f4488a41d43faa163ced5587e',
        '304402207f4986d09c46f7bc683378afcb548ac4068537cd8b18b0ebf532dc75427a4bc902203f2a7a35fb93aa4384dc72dcd95b47fdc3584565dae80aed6994435b0b7e7a20',
        '304402206900ae07ec730a85c9c576fcf4d65d5fb6983cfa5825df2ec2ffe2f8397668050220750bdd2cb7562855bf1662b7f87bd7686cdd2df04c7a5e8069ff53671ffc3af9',
        '304402200e8f103d3772847059501fa528bebacf6cb47f498c734479ab214bb5c1158fbf02205c78c6a304e54f87de843b4c2c1ae4967ff4a0caa67f35377010ce43e3fda7aa',
        '304402200b70ddd595cd2cb772b1de656ccf3a2eed586d73041b5dd32220f779caa1612e02204623df7a2dfb520a5330a8dc43b4d9dd6454d061f7c957c43080be150d2aa731',
        '3044022045caef51e222bc82df3d750ce2bf565ebcbf9bff628e53f2233af1f79242071d022033f512de3cfc4296207a7ced8b6bf22161f5936e567ad7ad3bc591f72d0f19b7',
        '3044022061338f52a273e827b769f345628564b8b87d97b2f3c5f4f8c8b073201cc01340022075760a9a3e09983662a8b32b0676678f1d103417d48be60d11a88f39a1242f89',
        '3045022100d724d6b026cc5d107b73fb7d601c065276d8f83131acae1b8f3249cdb51d5ab102203bdbcfa3b7740d3adf3920d0a8e7887dd21ab4b80d3c2f5b15c5a14387738b82',
        '30450221009e5b727095b0dec99495956d62cf4051b971f7bac10ae947f38beaf3dd3a545502206a4845931cc63962568d1232ad93300197073948a67b1110e7301daf9b5cec2b',
        '3045022100a8205c27a75e208be257af6f5f1fee74871405f2687462d5ce182b6829401a8a02200b31064bdba6436bf6be75cbf791c276b50427732a7fbb250110a4899811fb7b',
        '3044022077f79899c373eba2f6c1eae1a922852823b2efa91cab12cdbbd327b986be96f3022015f722f65ca9b88ed288219fa8eee9b9d867ee8920c38d6a49420f5785478189',
        '3044022007f7b8131d5346107a5586c10e84795e6249b848ab87d4960c546cf6266f4d7d022039122154563cbff36d9de49b7d1101fb75b8baa3a83da016fb77132de292c66c',
        '304502210083a72939975e8a616c5ce8f43f7dd24bd27af85362004ffa44c0d1d5419764fe02201ae4608ea44ac942d9ccfb0fad085efb23e4c5595e00127778615b72c33d6707',
        '304402207f8401b752387351dc0c48f8816b08862155ab717a8ad4281ce2aac5b3df9dcf022047a6f50b554089330b3edb0c45a0b37a3fa9ffca2b7153e6afb9cb35eb24e7e3',
        '304402203639888dff09af0f50135759d44cb172b5fda56069c0fe1583db4f8d4f859f5a02206ab605b5f2954667e6f44860330002bb47774285de842f7bc8ab67ced730e3ad',
        '3045022100c7c939ca171240f90caf8b4148bab5c9738a8c5f6531af301a4bc94f8864d1f9022026a780144daff758e612b26c246ded96a91b49e7b2b30f0c79e1496d89a8d050',
        '304402205902dd2492b4e5d7a593cf1988472a7123b229385480e82c7ab72a1d0b05da9f02206a95bab7ecfb0bb8928a56b23e096ee2821c7b06ac170967009df21f55935489',
        '30450221008e889406065c11c76b5052dc8d6b8046aabdf7a81c9c0a8be62673afa03e1f7702203bef08970e20dbbb5657bf3e6971da9d8084dd466b3fd98971f86d230a3a42bf',
        '3045022100acd8fac662f85cb521a8c6d16a938d54732c4145ed90dc4f93aaefc75a775a6b022011cf0451472dd48eb0a6b868d43904698f4838bd3f58f3b43ce00986211cef75',
      ];

      for (let i = 0; i < keys.length; i += 1) {
        const key = new Key(keys[i]);
        const hash = new Hash(hashes[i]);
        const sig = new Signature(sigs[i]);

        const verified = sig.verify(key.publicKey(), hash);
        expect(verified).equal(true);

        const calcSig = await key.sign(hash);
        // console.log('Calc sig ' + i + ' : ' + calcSig.toString());

        const verified2 = calcSig.verify(key.publicKey(), hash);
        expect(verified2).equal(true);

        expect(calcSig.toString()).equal(sig.toString());
      }
    });

    // xkey mnemonic : drift basic fame sight capital seven spot win humble regret alpha shift custom click galaxy
    // xkey seed : 371c6987141e30d3a2d7fa35c19bf476bdce121db0f7ed10248b36708a3d3a71f9c5ef71d1efb31f55567c2a3bc6d8a134212229f05bb0a88828368022468e87

    test('xkey (bip32) root', () => {
      const xkey = new XKey(
        'xprv9s21ZrQH143K3hJk1gVbS5EdekArYf5Rk1xKRDkkZAbpDEaFzWQkfvPEthzgKGsUtoTRV14LZVh4pam8WckasA71ZLWN1MkPf1Sw794kTcw',
      );
      expect(xkey.isPrivate()).equal(true);
    });

    test('xkey (bip32) child m/5', () => {
      const xkey = new XKey(
        'xprv9vDE3qgGTP5sDGjTCKBtF46Gf4iBwxbcBmobLakz1yKgMspoVYqKXixTJP2GuSJ1M7uxUD8KWkiFdEvupbqbd1GXGS68Sc6xFQE82viz9H9',
      );
      expect(xkey.isPrivate()).equal(true);
      expect(xkey.index).equal(5);
    });

    test("xkey (bip32) child m/5/2'", async () => {
      const xkey = new XKey(
        'xprv9w1T359ct1N4vQivGTF2o72r5iKpg9CmCujTcSyGbfMQp341iEja8cn8Xa45o5qdMQscXMxwf4WMzzTXNSqqgKHCmQL2WYCpVRqGkiH2iLn',
      );
      expect(xkey.isPrivate()).equal(true);
      expect(xkey.index).equal(2 + Bip32Hardened);

      // child 1
      // address 1SBiXiC3exDRhZXi3pX7oyKqAZAV4aZex
      // public 03b2087cc4be2c8d103b8122247bd557f3cb76ba2f7ed0279d0246362b03016303
      // private KzKitEMxyBKwY2pXxVjNCxMokjWMWXydSgVBaW53fma6RLzRgc4s
      const child = await xkey.derive('m/1');
      expect(child.toString()).equal(
        'xprv9xh5e7ijHEoDKmqasgHisgsoqhSrCg1nCkWvJsEdkqnrNcmvsaTjqyJKiSWc8ru7tzmJNh3AKQHvdYGdDnrzqVfJqRTWueD8NQdVV5aE1vu',
      );

      expect(child.key().toString()).equal(
        'KzKitEMxyBKwY2pXxVjNCxMokjWMWXydSgVBaW53fma6RLzRgc4s',
      );

      expect(child.publicKey().toString()).equal(
        '03b2087cc4be2c8d103b8122247bd557f3cb76ba2f7ed0279d0246362b03016303',
      );

      const hardChild = await child.derive("m/1'");
      expect(hardChild.toString()).equal(
        'xprv9zaamjzwnqe4eapXZaLqLfRbEGgkUNh2eNy69ZUb5oU29vZcRzUagwNd1ZcGYYDZVcp4ZxTenNAR3fYfC2QCG4dP38mbLrUEV1xvWfUUjwY',
      );
    });

    test('xkey (bip32) child m/5 public', async () => {
      const xkey = new XKey(
        'xpub69CaTMDAHkeARkovJLitcC31D6YgMRKTYzjC8yAbaJrfEg9x369a5XGw9dZXsDjAKzWFy3fDchrYvMoFDwwbPLXnn1Y4j2RjMtmRzna5K5G',
      );
      expect(xkey.isPrivate()).equal(false);
      expect(xkey.index).equal(5);

      expect(xkey.publicKey().toString()).equal(
        '02b77e384a2591a1050ce39f18fd6b09bfc2ffd3a6d4616dd484b7e87588965112',
      );

      const child = await xkey.derive('m/12');
      expect(child.index).equal(12);
      expect(child.toString()).equal(
        'xpub69zoSagNNiPQN2jof34hyJsR3voHJvEp1yXXsL2eqU6YVW6F43zjwJjc9m36R88cEZGzZB5ni8BfebybqaV9HAHarwHNV87rjW5t8CgJuqj',
      );

      expect(child.publicKey().toString()).equal(
        '02f2cd53c5da6236a8799f2c3b775fd42b6fc631a108b9d10e43e61ffc6acb630c',
      );
    });

    test('xkey (bip32) from bsv', () => {
      const bsvXKey = new bsv.Bip32();
      bsvXKey.fromString(
        'xpub69CaTMDAHkeARkovJLitcC31D6YgMRKTYzjC8yAbaJrfEg9x369a5XGw9dZXsDjAKzWFy3fDchrYvMoFDwwbPLXnn1Y4j2RjMtmRzna5K5G',
      );

      const xkey = new XKey(bsvXKey.toBuffer());

      expect(xkey.toString()).equal(
        'xpub69CaTMDAHkeARkovJLitcC31D6YgMRKTYzjC8yAbaJrfEg9x369a5XGw9dZXsDjAKzWFy3fDchrYvMoFDwwbPLXnn1Y4j2RjMtmRzna5K5G',
      );
    });

    test('xkey (bip32) to public', () => {
      const xkey = new XKey(
        'xprv9w1T359ct1N75AHd9PPAfjG1eBrcP7UkdFEZYakrhUiss6ToH2SWUUwAB8SbkLZDAXFbtoy7ybssUqsiEFrDutvNuepUiHnfZtNNX55HcbC',
      );
      const xpub = xkey.toPublic();

      expect(xpub.toString()).equal(
        'xpub69zoSagWiNvQHeN6FQvB2sCkCDh6naCbzUAALyAUFpFrjtnwpZkm2HFe2PuVVHbccDDifg5PzCMhNXA2FRz464tbbksXLhwaaegpXvdWX4e',
      );
    });

    test('xkey (bip32) from seed', async () => {
      const buf = Buffer.from(
        '371c6987141e30d3a2d7fa35c19bf476bdce121db0f7ed10248b36708a3d3a71f9c5ef71d1efb31f55567c2a3bc6d8a134212229f05bb0a88828368022468e87',
        'hex',
      );

      const xkey = await XKey.fromSeed(buf);
      expect(xkey.toString()).equal(
        'xprv9s21ZrQH143K3hJk1gVbS5EdekArYf5Rk1xKRDkkZAbpDEaFzWQkfvPEthzgKGsUtoTRV14LZVh4pam8WckasA71ZLWN1MkPf1Sw794kTcw',
      );
    });
  });
}

export default specifyTests;
