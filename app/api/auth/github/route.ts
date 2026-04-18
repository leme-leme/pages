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

	try {
    // Direct fetch instead of arctic's validateAuthorizationCode: arctic/oslo
    // sends `User-Agent: oslo` + form-encoded body, which Cloudflare's edge
    // in front of github.com/login/oauth/access_token rejects with
    // "Request forbidden by administrative rules". JSON body + default UA works.
    const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        client_id: process.env.GITHUB_APP_CLIENT_ID,
        client_secret: process.env.GITHUB_APP_CLIENT_SECRET,
        code,
      }),
    });
    if (!tokenResponse.ok) {
      throw new Error(`GitHub token exchange failed: ${tokenResponse.status} ${await tokenResponse.text()}`);
    }
    const tokenData = await tokenResponse.json() as { access_token?: string; error?: string; error_description?: string };
    if (!tokenData.access_token) {
      throw new Error(`GitHub token exchange error: ${tokenData.error_description ?? tokenData.error ?? "no access_token in response"}`);
    }
    const accessToken = tokenData.access_token;

		const githubUserResponse = await fetch("https://api.github.com/user", {
			headers: {
				Authorization: `Bearer ${accessToken}`,
				"User-Agent": "pages-cms"
			}
		});
		const githubUser: GitHubUser = await githubUserResponse.json();

    const { ciphertext, iv } = await encrypt(accessToken);

		const existingUser = await db.query.userTable.findFirst({
			where: eq(userTable.githubId, Number(githubUser.id))
		});

		if (existingUser) {
			await db.update(githubUserTokenTable).set({
				ciphertext, iv
			}).where(
				eq(githubUserTokenTable.userId, existingUser.id)
			);
			const session = await lucia.createSession(existingUser.id as string, {});
			const sessionCookie = lucia.createSessionCookie(session.id);
			cookies().set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
			return new Response(null, {
				status: 302,
				headers: {
					Location: "/"
				}
			});
		}

		const userId = generateIdFromEntropySize(10); // 16 characters long

		await db.insert(userTable).values({
			id: userId,
			githubId: Number(githubUser.id),
			githubUsername: githubUser.login,
			githubEmail: githubUser.email,
			githubName: githubUser.name
		});
    await db.insert(githubUserTokenTable).values({
			ciphertext,
			iv,
			userId
		});

		const session = await lucia.createSession(userId, {});
		const sessionCookie = lucia.createSessionCookie(session.id);
		cookies().set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
		return new Response(null, {
			status: 302,
			headers: {
				Location: "/"
			}
		});
	} catch (e) {
		console.error("GitHub auth error:", e);
		return new Response(null, { status: 500 });
	}
}

interface GitHubUser {
	id: string;
	login: string;
	email: string;
	name: string;
}