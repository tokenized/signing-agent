# Tokenized Signing Agent

An automated agent for signing transactions using the Tokenized protocol. Available as a CLI, HTTP server and NodeJS library.

## Quick start

### Prerequisites

- a file (here called `secrets.json`) containing the platform endpoint URL and client identifiers. Obtain this from Tokenized support.
- this software package, installed from NPM [https://npmjs.com/package/@tokenized/signing-agent] or source code [https://github.com/tokenized/signing-agent]
- NodeJS version 20 or later [https://nodejs.org/en/download]

```
npm i -g @tokenized/signing-agent
```

(if using a source checkout, use this instead: `npm i -g .`)

### Create a user

Obtain the development Tokenized desktop app and enable the `Compact pairing code` feature.

Sign up a new user for the signing agent.

### Pair the agent

When prompted to `Scan the mobile app pairing code`, copy the code and run (replacing `123456789` with the code on screen):

```
tokenized-signing-agent pair secrets.json 123456789 :generate
```

A 24 word seed phrase will be printed on screen. Store this appropriately, being aware that it cannot be recreated and in the wrong hands could be used to steal funds. In the event of loss of the secrets.json file this seed phrase will be needed to recover the signing agent, otherwise the signing agent will need to be re-created and the workspace migrated to the new control arrangement.

After this point the `secrets.json` will contain:

- the Tokenized platform API endpoint
- client identifier and secret specific to your installation
- a secret used to authorize the client to contact the API on behalf of your newly created user
- a secret used to unlock the root key for signing purposes.

### Create a workspace to hold funds

Create a new workspace (in the desktop app) and invite the signing agent and another administrator with manual signing access in a 1 of 2 signing arrangement. Accept the invitiation to the signing agent to join that workspace:

```
tokenized-signing-agent accept secrets.json <workspace-handle>
```

### Test the token send functionality

Acquire tokens in the fund holding workspace, replace `instrumentID` with the one from the Tokenized desktop app, and replace `me@tkz.id` with your workspace handle and `you@tkz.id` with the recipient's handle. The amount is in the instrument's minor units (for example cents rather than dollars)

```
tokenized-signing-agent send secrets.json me@tkz.id you@tkz.id instrumentID 20
```

### Run an HTTP server

```
tokenized-signing-agent serve secrets.json 8080
```

Note this server is unauthenticated and unencrypted and should only be accessible within a secure environment.

```
curl -d '{"from": "me@tkz.id", "to": "you@tkz.id", "instrument": "instrumentID","amount": 20}' http://localhost:8080/send
```

### Explore the CLI

```
tokenized-signing-agent help
```

### Use the library

```js
import { API } from "@tokenized/signing-agent";

const api = new API({
  endpoint: "https://url.of.tokenized.platform/",
  clientId: "id-Tokenized-sent-me",
  clientKey: "secret-Tokenized-sent-me",
  keyId: "id-generated-when-I-paired",
  privateJWK: { d: "secret-generated-when-I-paired" },
  deviceId: "id-generated-when-I-paired",
  encryptionSecret: { k: "secret-key-used-to-decrypt-root-key" },
  rootKeyId: "id-of-root-key",
});

await api.send("me@tkz.id", "you@tkz.id", "COUMes...Wea", 20);
```
