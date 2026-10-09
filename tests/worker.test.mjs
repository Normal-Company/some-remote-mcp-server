import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, test } from "node:test";
import { setTimeout } from "node:timers/promises";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";

let worker;
let origin;
let stateDirectory;
let output = "";

before(async () => {
	const socket = createServer();
	await new Promise((done) => socket.listen(0, "127.0.0.1", done));
	const port = socket.address().port;
	await new Promise((done) => socket.close(done));
	origin = `http://127.0.0.1:${port}`;
	stateDirectory = await mkdtemp(join(tmpdir(), "remote-mcp-test-"));
	worker = spawn(process.execPath, [
		resolve("node_modules/wrangler/bin/wrangler.js"), "dev", "--local",
		"--ip", "127.0.0.1", "--port", String(port), "--persist-to", stateDirectory,
	], { env: { ...process.env, WRANGLER_SEND_METRICS: "false", BROWSER: "none" } });
	for (const stream of [worker.stdout, worker.stderr]) {
		stream.on("data", (chunk) => { output = (output + chunk).slice(-8000); });
	}
	for (let attempt = 0; attempt < 150; attempt++) {
		if (worker.exitCode !== null) throw new Error(`Worker exited: ${output}`);
		try {
			const response = await fetch(`${origin}/.well-known/oauth-authorization-server`, {
				signal: AbortSignal.timeout(1000),
			});
			if (response.ok) return;
		} catch { /* Wait for the local runtime to bind its port. */ }
		await setTimeout(200);
	}
	throw new Error(`Worker did not become ready: ${output}`);
}, { timeout: 45000 });

after(async () => {
	if (worker && worker.exitCode === null) {
		worker.kill("SIGTERM");
		await Promise.race([
			new Promise((done) => worker.once("exit", done)),
			setTimeout(3000).then(() => worker.kill("SIGKILL")),
		]);
	}
	if (stateDirectory) await rm(stateDirectory, { recursive: true, force: true });
});

test("OAuth discovery describes this worker and its protected resource", async () => {
	const resourceResponse = await fetch(`${origin}/.well-known/oauth-protected-resource`);
	assert.equal(resourceResponse.status, 200);
	const resource = await resourceResponse.json();
	assert.equal(resource.resource, origin);
	assert.deepEqual(resource.authorization_servers, [origin]);
	const server = await (await fetch(`${origin}/.well-known/oauth-authorization-server`)).json();
	assert.equal(server.authorization_endpoint, `${origin}/authorize`);
	assert.equal(server.token_endpoint, `${origin}/token`);
	assert.equal(server.registration_endpoint, `${origin}/register`);
	assert.ok(server.code_challenge_methods_supported.includes("S256"));
});

test("unauthenticated MCP access is rejected", async () => {
	const response = await fetch(`${origin}/sse`, { headers: { Accept: "text/event-stream" } });
	assert.equal(response.status, 401);
	assert.match(response.headers.get("www-authenticate"), /Bearer/);
});

test("public OAuth client registration works in isolated local storage", async () => {
	const response = await fetch(`${origin}/register`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			client_name: "Local smoke test",
			redirect_uris: [`${origin}/test-callback`],
			token_endpoint_auth_method: "none",
			grant_types: ["authorization_code"], response_types: ["code"],
		}),
	});
	assert.equal(response.status, 201);
	const client = await response.json();
	assert.equal(typeof client.client_id, "string");
	assert.deepEqual(client.redirect_uris, [`${origin}/test-callback`]);
});

test("the demo PKCE login permits an authenticated MCP add call", { timeout: 15000 }, async () => {
	const redirectUri = `${origin}/test-callback`;
	const registration = await fetch(`${origin}/register`, {
		method: "POST", headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			client_name: "Local MCP test", redirect_uris: [redirectUri],
			token_endpoint_auth_method: "none",
			grant_types: ["authorization_code"], response_types: ["code"],
		}),
	});
	assert.equal(registration.status, 201);
	const { client_id: clientId } = await registration.json();
	const verifier = randomBytes(32).toString("base64url");
	const challenge = createHash("sha256").update(verifier).digest("base64url");
	const query = new URLSearchParams({
		client_id: clientId, redirect_uri: redirectUri, response_type: "code",
		code_challenge: challenge, code_challenge_method: "S256", scope: "read_data",
	});
	const authorize = await fetch(`${origin}/authorize?${query}`);
	assert.equal(authorize.status, 200);
	const form = (await authorize.text()).match(/name="oauthReqInfo"\s+value="([^"]+)"/);
	assert.ok(form, "authorization page contains its request form");
	const entities = { "&quot;": '"', "&#39;": "'", "&lt;": "<", "&gt;": ">", "&amp;": "&" };
	const requestInfo = form[1].replace(/&quot;|&#39;|&lt;|&gt;|&amp;/g, (value) => entities[value]);
	const approval = await fetch(`${origin}/approve`, {
		method: "POST", body: new URLSearchParams({
			action: "approve", oauthReqInfo: requestInfo, email: "local-test@example.com",
		}),
	});
	assert.equal(approval.status, 200);
	const redirect = (await approval.text()).match(/window.location.href = "([^"]+)"/);
	assert.ok(redirect, "demo approval produces a redirect");
	const code = new URL(redirect[1]).searchParams.get("code");
	assert.ok(code, "redirect contains an authorization code");
	const tokenResponse = await fetch(`${origin}/token`, {
		method: "POST", body: new URLSearchParams({
			grant_type: "authorization_code", client_id: clientId,
			redirect_uri: redirectUri, code, code_verifier: verifier,
		}),
	});
	assert.equal(tokenResponse.status, 200);
	const token = await tokenResponse.json();
	assert.ok(token.access_token);
	const authenticatedFetch = (url, init = {}) => {
		assert.equal(new URL(url).origin, origin, "test requests stay local");
		const headers = new Headers(init.headers);
		headers.set("Authorization", `Bearer ${token.access_token}`);
		return fetch(url, { ...init, headers });
	};
	const client = new Client({ name: "smoke-test", version: "1.0.0" });
	const transport = new SSEClientTransport(new URL(`${origin}/sse`), {
		fetch: authenticatedFetch, eventSourceInit: { fetch: authenticatedFetch },
	});
	try {
		await client.connect(transport);
		const result = await client.callTool({ name: "add", arguments: { a: 2, b: 3 } });
		assert.deepEqual(result.content, [{ type: "text", text: "5" }]);
	} finally {
		await client.close();
	}
});
