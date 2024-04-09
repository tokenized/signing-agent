import Tx from './Tx.js';
import { hexToArrayBuffer } from './utils.js';

export function assembleTransactionFromApiResponse(response) {
  const {
    tx: rawUnsignedTx,
    input_supplements: inputSupplements,
    output_supplements: outputSupplements,
  } = response.data;

  const tx = new Tx(rawUnsignedTx);
  tx.inputSupplements = inputSupplements;
  tx.outputSupplements = outputSupplements;
  return tx;
}

export async function assembleTransactionFromApiResponseWithOriginalFee(
  response,
  rootKey,
  vaultPath,
) {
  const tx = assembleTransactionFromApiResponse(response);
  const signedTx = await signRawTransaction(tx, rootKey, vaultPath);
  console.log(`Signed TxID: ${await tx.id('hex')}`);
  return signedTx;
}

async function signInput(tx, rootKey, vaultPath, inputSupplement, index) {
  const path = inputSupplement.key_id.replace('m', vaultPath);
  const childKey = await rootKey.makeChildKey(path);
  const lockingScriptBuf = hexToArrayBuffer(inputSupplement.locking_script);
  await tx.signP2PKHInput(
    childKey.key(),
    index,
    lockingScriptBuf,
    inputSupplement.value,
  );
}

export async function signRawTransaction(tx, rootKey, vaultPath) {
  console.log(
    `Transaction.signRawTransaction: doing signInput ${tx.inputSupplements.length} times`,
  );
  console.time('Transaction.signRawTransaction');
  for (let i = 0; i < tx.inputSupplements.length; i += 1) {
    if (tx.inputSupplements[i]?.key_id) {
      // Note: these could all be done in “parallel” with Promise.all, but it
      // makes no difference to the total time taken. Doing it that way also
      // makes the first time through much slower, presumably because all the
      // signing calls see that there’s no cached seed value together, and all
      // of them end up doing the full derivation. That could be fixed by doing the
      // first one serially, but to get any benefit we’d need proper multithreading
      // (Web Workers)
      await signInput(tx, rootKey, vaultPath, tx.inputSupplements[i], i);
    }
  }
  console.timeEnd('Transaction.signRawTransaction');
  return tx;
}
