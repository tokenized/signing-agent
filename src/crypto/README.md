# Bitcoin Transaction Signing

This is a javascript library for reading, signing, and writing raw bitcoin
transactions.

The use case this is designed for is when a serialized bitcoin tx is received
that already contains inputs and needs them signed. It requires knowledge of the
outputs being spent and the private key. It currently only supports P2PKH
locking scripts.

### Reading Transactions

Read the transaction using the constructor. The argument can be a hex string or
an `ArrayBuffer`, or a Node.js `Buffer` is also supported.

```javascript
var tx = new Tx(data);
```

### Signing Transactions

The private key and the locking script and value from the UTXO being spent are
required to create the signature.

The private key must be a `Key` from this library which can be created with the
constructor using a base58 encoded key or raw bytes representing the 32 byte
integer. Add the signatures using the `signP2PKHInput` function. By default, the
signature uses a sighash type of `Tx.SIGHASH_ALL | Tx.SIGHASH_FORKID`, this can
be changed by appending another parameter to the `signP2PKHInput()` call.

```javascript
var privateKey = Key('wif key string');
var inputIndex = 0;
tx.signP2PKHInput(privateKey, inputIndex, utxo.lockingScript, utxo.value);
```

### Writing Transactions

The transaction can be serialized for transmission using the `toString` and
`toBytes` functions which return a hex string or `ArrayBuffer` containing binary
data, respectively.

```javascript
var hex = tx.toString();
var buf = tx.toBytes();
```
