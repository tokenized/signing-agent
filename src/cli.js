#!/usr/bin/env node
import API from "./Api.js";
import { createSecretJWK, createSecretKeyBytes, encrypt } from "./crypto/Encryption.js";
import { entropyToMnemonic } from "./crypto/bip39Mnemonic.js";
import { normalizeMnemonic } from "./crypto/mnemonic.js";
import { httpServe } from "./server.js";
import { mnemonicToEntropy } from "./x.bip39Mnemonic.js";
import { readFile, writeFile } from "node:fs/promises";

class Config {
    constructor(configPath, settings) {
        this.configPath = configPath;
        this.settings = settings;
        this.api = new API(settings);
    }

    update(settings) {
        this.settings = { ...this.settings, ...settings };
    }

    async save() {
        if (!this.configPath) {
            throw "No configuration file to write";
        }
        await writeFile(this.configPath, JSON.stringify(this.settings, null, 4), { encoding: "utf8" });
    }

    static async load(configSource) {
        let configText, configPath;
        if (configSource.startsWith("env:")) {
            configText = configSource.slice("env:".length);
        } else {
            configText = await readFile(configSource, { encoding: "utf8" })
            configPath = configSource;
        }
        return new Config(configPath, JSON.parse(configText));
    }
}


async function init(configPath, endpoint) {
    const config = new Config(configPath, { endpoint });
    await config.save();
}

/** @param {Config} config */
async function configureSeedPhrase(config, seedPhraseOptions) {

    const encryptionSecret = await createSecretJWK();
    let entropy;
    let rootKeyId;
    let seedPhrase;

    let create = seedPhraseOptions == ":generate" || seedPhraseOptions == ":silent";
    if (create) {
        entropy = await createSecretKeyBytes();
        seedPhrase = await entropyToMnemonic(entropy);
        if (seedPhraseOptions != ":silent") {
            console.log("Seed phrase:");
            console.log(seedPhrase);
        }
    } else {
        seedPhrase = normalizeMnemonic(await readFile(seedPhraseOptions, { encoding: "utf8" }));
        entropy = await mnemonicToEntropy(seedPhrase);
        rootKeyId = await config.api.verifySeedPhrase(seedPhrase);
    }
    const encryptedEntropy = await encrypt(entropy, encryptionSecret);

    rootKeyId = await config.api.storeEncryptedRootKey(encryptedEntropy, rootKeyId);
    if (create) {
        await config.api.registerXPub(seedPhrase);
    }
    config.update({ rootKeyId, encryptionSecret });
    await config.save();
}

async function seed(configPath, seedPhrase) {
    const config = await Config.load(configPath);
    await configureSeedPhrase(config, seedPhrase);
}

seed.help = `
signing-agent seed <secrets.json> <seed phrase options>
    Configure a seed phrase for signing

<seed phrase options>
:generate
    Generate and print a seed phrase
:silent
    Generate and do not print a seed phrase
<seed-phrase-file>
    Use an existing (previously paired for this account) seed phrase
`;

async function pair(configPath, handle, pairingCode, seedPhraseOptions) {
    const config = await Config.load(configPath);
    config.update(await config.api.pair(pairingCode));
    await config.save();
    if (seedPhraseOptions) {
        await configureSeedPhrase(config, handle, seedPhraseOptions);
    }
}

pair.help = `
signing-agent pair <secrets.json> [<seed phrase options>]
    Pair this agent with a user account and optionally configure a seed phrase
`;

async function activate(configPath, handle) {
    const config = await Config.load(configPath);
    await config.api.registerXPub(await config.api.getSeedPhrase(config.api.rootKeyId), handle);
}

activate.help = `
signing-agent activate <secrets.json> <handle>
    Activate a handle for a workspace to which the signing user has been invited
`

async function send(configPath, fromHandle, toHandle, instrumentId, amount) {
    const config = await Config.load(configPath);
    let { activity, txids } = await config.api.send(fromHandle, toHandle, instrumentId, amount);
    console.log("Activity:", activity);
    console.log("txids:", ...txids)
}

function help() {
    console.log("Tokenized protocol signing agent");
    console.log(Object.values(commands).map(command => command.help).filter(Boolean).join("\n"));
}


async function serve(configSource, port) {
    const { api } = await Config.load(configSource);
    await httpServe(api, Number(port));
}


const [command, ...args] = process.argv.slice(2);

const commands = { init, pair, seed, send, serve, activate };

try {
    await (commands[command] || help)(...args);
} catch (e) {
    console.log("ERROR:", e);
    process.exit(1);
}