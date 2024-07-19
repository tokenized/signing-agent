//@ts-check
import XKey from "./crypto/XKey.js";
import { generateECDSAJWK, importPrivateKey } from "./jwk.js";
import { createJWT, expiredFraction } from "./jwt.js";
import { mnemonic2Seed } from "./crypto/mnemonic.js";
import Tx from "./crypto/Tx.js";
import { decrypt } from "./crypto/Encryption.js";
import { hexToArrayBuffer } from "./crypto/utils.js";
import { entropyToMnemonic } from "./crypto/bip39Mnemonic.js";

/**
 * @param {TemplateStringsArray} template
 * @param {any[]} parameters
 */
function url([first, ...strings], ...parameters) {
  return (
    first +
    parameters
      .map((key, index) => encodeURIComponent(key) + strings[index])
      .join('')
  );
}

class APIError extends Error {
  constructor(message, status, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

export default class API {
  constructor({ clientId, clientKey, keyId, privateJWK, endpoint, deviceId, encryptionSecret, rootKeyId }) {
    this.clientId = clientId;
    this.clientKey = clientKey;
    this.keyId = keyId;
    this.privateJWK = privateJWK;
    this.endpoint = endpoint;
    this.deviceId = deviceId;
    this.encryptionSecret = encryptionSecret;
    this.rootKeyId = rootKeyId;
  }

  async updateDeviceAuthToken() {
    if (!this.privateJWK) throw "Pairing not found";
    const privateKey = await importPrivateKey(this.privateJWK);

    let singleUseJWT = await createJWT(this.keyId, privateKey, {
      jti: `${Date.now()}`,
    });

    const { data: { token } } = await this.fetch("GET", url`auth/token/device`, null, singleUseJWT);

    this.tokenCreatedAt = Date.now() / 1e3;
    this.jwt = token;
    this.updateTokenPromise = null;
  }

  async pair(pairingCode) {
    const { keyId, privateJWK, publicJWK } = await generateECDSAJWK();

    const { data: { id: deviceId } } = await this.fetch(
      "POST",
      url`users/@me/devices/code`,
      {
        pairing_code: pairingCode,
        client_key: this.clientKey,
        client_id: this.clientId,
        external_id: this.clientId,
        public_key: JSON.stringify(publicJWK),
        key_id: keyId,
        is_active: true,
        provider_name: `signing-agent-1`,
        manufacturer_name: '',
        device_name: 'Pairing',
        provider_id: 'File:-',
      },
      false,
    );

    this.privateJWK = privateJWK;
    this.keyId = keyId;
    this.deviceId = deviceId;

    return { privateJWK, keyId, deviceId };
  }

  static async makeXPub(seedPhrase, path) {
    const rootKey = await XKey.fromSeed(await mnemonic2Seed(seedPhrase))
    const xKey = await rootKey.derive(path);
    return xKey.toPublic().toString();
  }

  static async makeXPubInternal(seedPhrase, path) {
    const rootKey = await XKey.fromSeed(await mnemonic2Seed(seedPhrase))
    const xKey = await rootKey.derive(path);
    return Buffer.from(xKey.toPublic().toInternalBytes()).toString("hex");
  }

  async verifySeedPhrase(seedPhrase) {
    const { data: rootKeys } = await this.fetch("GET", url`users/@me/rootkeys`);
    if (!rootKeys?.length) return null;

    for (let { id: rootKeyId } of rootKeys) {
      try {
        const { data: { derivation_path } } = await this.fetch("GET", url`users/@me/rootkeys/${rootKeyId}/check`);
        const xpub = await API.makeXPub(seedPhrase, derivation_path);
        await this.fetch("POST", url`users/@me/rootkeys/${rootKeyId}/check`, { derivation_path, xpub });
        return rootKeyId;
      } catch (e) {
        if (e.status == 404) {
          continue;
        }
        throw new Error(`Unable to verify seed phrase: ${e}`);
      }
    }
  }

  async registerXPub(seedPhrase, handle = null) {
    const { data: proposals } = await this.fetch("GET", url`proposals`);

    const personalProfile = proposals.find(proposal => proposal.invited_profile_id);
    const proposal = proposals.find(proposal => handle ? proposal.handle == handle : proposal.id == personalProfile.id);

    if (!proposal?.lockbox_id) throw "Invitation not found for handle";

    const lockboxId = proposal.lockbox_id;
    const profileId = personalProfile.invited_profile_id;

    const { data: { path } } = await this.fetch(
      "GET",
      url`profiles/${profileId}/lock_boxes/${lockboxId}/rootkeys/${this.rootKeyId}/proposal`
    );
    const xpub = await API.makeXPub(seedPhrase, path);
    await this.fetch(
      "POST",
      url`profiles/${profileId}/lock_boxes/${lockboxId}/rootkeys/${this.rootKeyId}/proposal`,
      { path, xpub }
    );

    return proposal.handle;
  }

  async storeEncryptedRootKey(encryptedEntropy, rootKeyId) {
    const body = {
      id: rootKeyId,
      encrypted: encryptedEntropy.toString('hex'),
      device_id: this.deviceId,
    };
    try {
      const { data: { id } } = await this.fetch("POST", url`users/@me/rootkeys`, body);
      this.rootKeyId = id;
      return id;
    } catch (e) {
      if (e.status == "409") throw "Root key already registered";
      throw e;
    }
  }

  async getRootkeys() {
    const { data: rootkeys } = await this.fetch("GET", url`users/@me/rootkeys`);
    return rootkeys || [];
  }

  async hasRootkeys() {
    return (await this.getRootkeys()).length;
  }

  async getEncryptedRootKey(rootKeyId) {
    const { data: rootkeys } = await this.fetch("GET", url`users/@me/rootkeys`);
    let rootKey = rootkeys.find(({ id, device_id }) => (!rootKeyId || id == rootKeyId) && device_id == this.deviceId);
    if (!rootKey) {
      throw "Root key not found";
    }
    return Buffer.from(rootKey?.encrypted, "hex");
  }

  async getHandleProposal(handle) {
    const { data: proposals } = await this.fetch("GET", url`proposals`);

    const proposal = proposals.find(proposal => proposal.handle == handle);

    if (!proposal) throw new APIError("Signing handle not found", 404, { code: "HANDLE_NOT_FOUND" });
    if (!proposal?.is_accepted) throw new APIError("Handle not yet activated", 404, { code: "HANDLE_NOT_ACTIVE" });

    return proposal;
  }

  async signHandshake(fromHandle, handshakeId) {
    let { profile_id: profileId } = await this.getHandleProposal(fromHandle);

    let { data: handshakes } = await this.fetch(
      "GET", url`auth/handshakes`
    );

    let handshake = handshakes.find(({ id }) => id == handshakeId);
    if (!handshake) {
      throw new APIError("Handshake not found", 404, { code: "HANDSHAKE_NOT_FOUND" });
    }

    let { request_id: requestId, scope } = handshake;

    let result;

    if (scope == "trade_reject") {
      await this.fetch("POST",
        url`profiles/${profileId}/requests/${requestId}/reject`,
        {},
      );

      result = { rejected: true };
    } else if (scope == "reject_proposal") {
      await this.fetch("POST",
        url`profiles/${profileId}/pending_transactions/requests/${requestId}/reject`,
        {},
      );

      result = { rejected: true };
    } else {
      const { data: pendingTransaction } = await this.fetch(
        "GET", url`profiles/${profileId}/pending_transactions/request_id/${requestId}`
      );

      if (!pendingTransaction) {
        throw new APIError("Pending transaction not found", 404, { code: "PENDING_TRANSACTION_NOT_FOUND" });
      }

      let txIds = await this.sign(profileId, pendingTransaction);

      result = { signed: true, txIds };
    }

    await this.fetch("PUT", url`auth/handshakes`, {
      handshake_id: handshakeId,
      device_id: this.deviceId,
      status: "approved"
    });

    return result;
  }


  async send(fromHandle, toHandle, instrument, amount) {
    let { lockbox_id: lockboxId, profile_id: profileId } = await this.getHandleProposal(fromHandle);

    const body = {
      lock_box_id: lockboxId,
      recipients: [{ handle: toHandle, amount: Number(amount) }],
      instrument
    };
    const { data: { activity_id } } = await this.fetch("PUT", url`profiles/${profileId}/send`, body).catch(e => {
      if (e.details.code) {
        throw e;
      }
      throw new APIError("Send failed", 400, { code: "SEND_FAILED" });
    });

    while (true) {
      const { data: { transactions } } = await this.fetch("GET", url`profiles/${profileId}/activity/${activity_id}`);

      let pending = transactions.filter(({ type }) => type == "pending_tx");

      if (!pending.length) {
        console.error("Waiting for pending transactions to sign");
        await new Promise(resolve => setTimeout(resolve, 250));
        continue;
      }

      const { pending_transaction_id } = pending[0];

      await this.signPendingTxId(profileId, pending_transaction_id);
      break;
    }

    let patience = 80;
    while (true) {
      const { data: { stage, transactions, termination_reason } } = await this.fetch("GET", url`profiles/${profileId}/activity/${activity_id}`);

      if (patience-- > 0 && stage != "executed" && !termination_reason) {
        console.error("Waiting for completion");
        await new Promise(resolve => setTimeout(resolve, 250));
        continue;
      }

      return transformActivity(transactions, termination_reason, activity_id, stage);
    }
  }

  async describe(handle, activity_id) {
    const { data: proposals } = await this.fetch("GET", url`proposals`);

    const proposal = proposals.find(proposal => proposal.handle == handle);
    if (!proposal) throw new APIError("Handle not found", 404, { code: "HANDLE_NOT_FOUND" });
    const profileId = proposal.profile_id;

    const { data: { stage, transactions, termination_reason } } = await this.fetch("GET", url`profiles/${profileId}/activity/${activity_id}`);

    return transformActivity(transactions, termination_reason, activity_id, stage);
  }



  async getSeedPhrase(rootKeyId) {
    const encryptedEntropy = await this.getEncryptedRootKey(rootKeyId);
    const decryptedEntropy = await decrypt(encryptedEntropy, this.encryptionSecret);
    return await entropyToMnemonic(decryptedEntropy);
  }

  async sign(profileId, pendingTransaction) {
    const tx = new Tx(pendingTransaction.tx);
    const signatures = [];
    for (let [index, input] of pendingTransaction.input_supplements.entries()) {

      if (!input.needed_signatures) {
        continue;
      }

      const lockingScriptBuf = hexToArrayBuffer(input.locking_script);

      for (let needed of input.needed_signatures) {
        const seedPhrase = await this.getSeedPhrase(needed.root_key_id);
        const mnemonicSeed = await mnemonic2Seed(seedPhrase);
        const rootXKey = await XKey.fromSeed(mnemonicSeed);

        const childKey = await rootXKey.derive(needed.derivation_path);
        signatures.push(await tx.makePendingTransactionSignature(
          childKey.key(),
          index,
          lockingScriptBuf,
          input.value,
          needed.signature_index,
          needed.sig_hash_type,
        ));
      }
    }

    const response = await this.fetch(
      "POST",
      url`profiles/${profileId}/pending_transactions/${pendingTransaction.id}`,
      { signatures }
    );

    let txId = await tx.id("hex");

    if (response?.data) {
      return [txId, ...await this.sign(profileId, response?.data)];
    }

    return [txId];
  }

  async signPendingTxId(profileId, pendingTransactionId) {
    const response = await this.fetch(
      "GET", url`profiles/${profileId}/pending_transactions/${pendingTransactionId}`
    );

    return await this.sign(profileId, response.data);
  }

  async getToken() {
    if (!this.jwt || expiredFraction(this.jwt, this.tokenCreatedAt) > 0.5) {
      await (this.updateTokenPromise ||= await this.updateDeviceAuthToken());
    }
    return this.jwt;
  }

  async fetch(method, urlSuffix, body, token) {
    if (token === undefined) {
      token = await this.getToken();
    }

    let response = await fetch(
      new URL(urlSuffix, this.endpoint),
      {
        method,
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: body ? JSON.stringify(body) : undefined
      }
    );

    if (!response.ok) {
      const error = new Error(`API Error: ${response.status}`);
      let body = await response.text();
      let details = body;
      try {
        details = JSON.parse(body);
      } catch (e) { }
      // @ts-ignore
      error.details = details;
      // @ts-ignore
      error.status = response.status;
      throw error;
    }

    return response.headers.get("Content-type") ? await response.json() : await response.text();
  }
}

function transformActivity(transactions, termination_reason, activity_id, stage) {
  let txs = transactions.filter(({ type }) => type == "tx").map(({ txid }) => txid);

  if (termination_reason) {
    throw new APIError("Not successful", 400, { activity: activity_id, txs, executed: false, termination_reason, stage });
  }

  return { activity: activity_id, txs, executed: stage == "executed", stage };
}

