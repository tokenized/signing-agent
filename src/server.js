import { once } from 'node:events';
import http from 'node:http';
import API from './Api.js';

async function readAll(stream) {
    let blocks = [];
    for await (let block of stream) {
        blocks.push(block);
    }
    return Buffer.concat(blocks);
}

const help = `
Tokenized signing agent server.
curl -d '{"from": "me@tkz.id", "to": "you@tkz.id", "instrument": "instrumentId","amount": 100}' http://localhost:8080
`;

/** @param {API} api */
async function send(api, [], {from, to, instrument, amount}) {
    console.log("Send from:", from, "to:", to, "instrument:", instrument, "amount:", amount);
    await api.send(from, to, instrument, amount);
    return {};
}


const actions = {POST: {send}};

/** @param {API} api */
export async function httpServe(api, port) {

    // Create a local server to receive data from
    const server = http.createServer(async (request, response) => {
        try {
            const body = JSON.parse(await readAll(request));
            
            const method = request.method;

            let [, action, ...rest] = request.url.split("/");

            if (!actions[method][action]) {
                response.writeHead(400, { 'Content-Type': 'text/plain' });
                response.end(help);
            } else {

                let result = await actions[method][action](api, rest, body);

                response.writeHead(200, { 'Content-Type': 'application/json' });
                response.end(JSON.stringify(result));
            }
        } catch (e) {
            console.log("Request error", e);
            response.writeHead(500, { 'Content-Type': 'text/plain' });
            response.end("Error");
        }
    });

    server.listen(port);
    await once(server, "listening");
    console.log("Listening")
}