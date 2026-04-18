import { redirect } from "next/navigation";
import { getAuth, lucia } from "@/lib/auth";
import { cookies } from "next/headers";
import { generateIdFromEntropySize } from "lucia";
import { encrypt } from "@/lib/crypto";
import { db } from "@/db";
import { userTable, githubUserTokenTable } from "@/db/schema";
import { eq } from "drizzle-orm";

/**
 * Handles GitHub OAuth authentication.
 * 
 * GET /api/auth/github
 * 
 * Requires GitHub OAuth code and state.
 */

export async function GET(request: Request): Promise<Response> {
	const { session } = await getAuth();
  if (session) return redirect("/");

	const url = new URL(request.url);
	const code = url.searchParams.get("code");
	const state = url.searchParams.get("state");
	const storedState = cookies().get("github_oauth_state")?.value ?? null;
	if (!code || !state || !storedState || state !== storedState) {
		return new Response(null, {
			status: 400
		});
	}

	let step = "init";
	try {
		step = "token_exchange";
		const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
			method: "POST",
			headers: { "Accept": "application/json", "Content-Type": "application/json" },
			body: JSON.stringify({
				client_id: process.env.GITHUB_APP_CLIENT_ID,
				client_secret: process.env.GITHUB_APP_CLIENT_SECRET,
				code,
			}),
		});
		if (!tokenResponse.ok) {
			throw new Error(`token_exchange http ${tokenResponse.status}: ${await tokenResponse.text()}`);
		}
		const tokenData = await tokenResponse.json() as { access_token?: string; error?: string; error_description?: string };
		if (!tokenData.access_token) {
			throw new Error(`token_exchange body: ${tokenData.error_description ?? tokenData.error ?? JSON.stringify(tokenData)}`);
		}
		const accessToken = tokenData.access_token;

		step = "fetch_user";
		const githubUserResponse = await fetch("https://api.github.com/user", {
			headers: { Authorization: `Bearer ${accessToken}`, "User-Agent": "pages-cms" }
		});
		if (!githubUserResponse.ok) {
			throw new Error(`fetch_user http ${githubUserResponse.status}: ${await githubUserResponse.text()}`);
		}
		const githubUser: GitHubUser = await githubUserResponse.json();

		step = "encrypt";
		const { ciphertext, iv } = await encrypt(accessToken);

		step = "find_existing_user";
		const existingUser = await db.query.userTable.findFirst({
			where: eq(userTable.githubId, Number(githubUser.id))
		});

		if (existingUser) {
			step = "update_token";
			await db.update(githubUserTokenTable).set({ ciphertext, iv })
				.where(eq(githubUserTokenTable.userId, existingUser.id));
			step = "create_session_existing";
			const session = await lucia.createSession(existingUser.id as string, {});
			const sessionCookie = lucia.createSessionCookie(session.id);
			cookies().set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
			return new Response(null, { status: 302, headers: { Location: "/" } });
		}

		step = "insert_user";
		const userId = generateIdFromEntropySize(10);
		await db.insert(userTable).values({
			id: userId,
			githubId: Number(githubUser.id),
			githubUsername: githubUser.login,
			githubEmail: githubUser.email,
			githubName: githubUser.name
		});
		step = "insert_token";
		await db.insert(githubUserTokenTable).values({ ciphertext, iv, userId });

		step = "create_session_new";
		const session = await lucia.createSession(userId, {});
		const sessionCookie = lucia.createSessionCookie(session.id);
		cookies().set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
		return new Response(null, { status: 302, headers: { Location: "/" } });
	} catch (e: any) {
		const msg = e?.message ?? String(e);
		const stack = e?.stack ?? "";
		console.error(`github_auth_error step=${step} msg=${msg}\n${stack}`);
		// TEMPORARY: surface error in response body while debugging. Remove once stable.
		return new Response(`github_auth step=${step}\n${msg}\n\n${stack}`, {
			status: 500,
			headers: { "Content-Type": "text/plain; charset=utf-8" }
		});
	}
}

interface GitHubUser {
	id: string;
	login: string;
	email: string;
	name: string;
}