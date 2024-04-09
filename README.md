# Tokenized Signing Agent

An automated agent for signing transactions using the Tokenized protocol. Available as a CLI, HTTP server and NodeJS library.

## Quick start

0) Prerequisites 
- a file called `secrets.json` containing the platform endpoint URL and client identifiers. Obtain this from Tokenized support.
- this software package, installed from NPM [https://npmjs.com/package/@tokenized/signing-agent] or source code [https://github.com/tokenized/signing-agent]
- NodeJS version 20 or later [https://nodejs.org/en/download]

`npm i -g @tokenized/signing-agent`

(if using a source checkout, use this instead: `npm i -g .`)

1) Obtain the development Tokenized desktop app and enable the `Compact pairing code` feature.

2) Sign up a new user for the purpose of automation.

3) When prompted to `Scan the mobile app pairing code`, copy the code and run (replacing `123456789` with the code on screen):

`signing-agent pair secrets.json 123456789`

A 24 word seed phrase will be printed on screen. Store this appropriately, being aware that it cannot be recreated and in the wrong hands could be used to steal funds. In the event of loss of the secrets.json file this seed phrase will be needed to recover the signing agent, otherwisde the signing agent will need to be re-created and the workspace migrated to the new control arrangement.

After this point the `secrets.json` will contain:
- the Tokenized platform API endpoint
- client identifier and secret specific to your installation
- a secret used to authorize the client to contact the API on behalf of your newly created user
- a secret used to unlock the root key for signing purposes.

4) Create a workspace to hold funds - add another administrator with manual signing access in a 1 of 2 signing arrangement. Invite the signing agent to join that workspace:

`signing-agent activate <workspace-handle>`

5) Test the token send functionality - obtain some tokens, replace `instrumentID` with the one from the Tokenized desktop app, and replace `me@tkz.id` and `you@tkz.id`. The amount is in the instrument's minor units (for example cents rather than dollars)

`signing-agent send secrets.json me@tkz.id you@tkz.id instrumentID 20`

6) Run an HTTP server:

`signing-agent serve secrets.json 8080`

Note this server is unauthenticated and unencrypted and should only be accessible within a secure environment.

`curl -d '{"from": "me@tkz.id", "to": "you@tkz.id", "instrument": "instrumentID","amount": 20}' http://localhost:8080`


