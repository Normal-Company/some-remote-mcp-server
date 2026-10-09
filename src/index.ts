import app from "./app";
import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import OAuthProvider from "@cloudflare/workers-oauth-provider";

export class MyMCP extends McpAgent {
	server = new McpServer({
		name: "Demo",
		version: "1.0.0",
	});

	async init() {
		this.server.tool("add", { a: z.number(), b: z.number() }, async ({ a, b }) => ({
			content: [{ type: "text", text: String(a + b) }],
		}));
	}
}

// Build metadata from the request origin for local and deployed environments.
export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const origin = new URL(request.url).origin;
		const oauth = new OAuthProvider<Env>({
			resourceMetadata: {
				resource: origin,
				authorization_servers: [origin],
				resource_name: "MCP Remote Auth Demo",
			},
			apiRoute: "/sse",
			apiHandler: MyMCP.mount("/sse"),
			defaultHandler: app,
			authorizeEndpoint: "/authorize",
			tokenEndpoint: "/token",
			clientRegistrationEndpoint: "/register",
		});
		return oauth.fetch(request, env, ctx);
	},
};
