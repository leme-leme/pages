/**
 * Auth helper functions for Lucia auth.
 */

import { cache } from "react";
import { Session, User, Lucia } from "lucia";
import { DrizzleSQLiteAdapter, SQLiteSessionTable, SQLiteUserTable } from "@lucia-auth/adapter-drizzle";
import { db } from "@/db";
import { userTable, sessionTable } from "@/db/schema";
import { GitHub } from "arctic";
import { cookies } from "next/headers";

// Lazy: db resolves per-request from the Cloudflare env binding; Lucia is built
// on first access so construction runs inside a request handler.
let _lucia: Lucia | null = null;
function getLucia(): Lucia {
	if (_lucia) return _lucia;
	const adapter = new DrizzleSQLiteAdapter(
		db as any,
		sessionTable as unknown as SQLiteSessionTable,
		userTable as unknown as SQLiteUserTable
	);
	_lucia = new Lucia(adapter, {
		sessionCookie: {
			expires: false,
			attributes: {
				secure: process.env.NODE_ENV === "production"
			}
		},
		getUserAttributes: (attributes) => ({
			githubId: attributes.githubId,
			githubUsername: attributes.githubUsername,
			githubEmail: attributes.githubEmail,
			githubName: attributes.githubName,
			email: attributes.email
		})
	});
	return _lucia;
}

export const lucia = new Proxy({} as Lucia, {
	get(_target, prop) {
		const instance = getLucia() as any;
		const value = instance[prop];
		return typeof value === "function" ? value.bind(instance) : value;
	}
});

declare module "lucia" {
	interface Register {
		Lucia: typeof lucia;
		DatabaseUserAttributes: DatabaseUserAttributes;
	}
}

export interface DatabaseUserAttributes {
	id: string;
	githubId: number;
	githubUsername: string;
	githubEmail: string;
	githubName: string;
	email: string;
}

// Lazy: Cloudflare Workers secrets aren't guaranteed at module init.
let _github: GitHub | null = null;
export const github = new Proxy({} as GitHub, {
	get(_target, prop) {
		if (!_github) {
			_github = new GitHub(
				process.env.GITHUB_APP_CLIENT_ID!,
				process.env.GITHUB_APP_CLIENT_SECRET!
			);
		}
		const value = (_github as any)[prop];
		return typeof value === "function" ? value.bind(_github) : value;
	}
});

export const getAuth = cache(
	async (): Promise<{ user: User; session: Session } | { user: null; session: null }> => {
		const sessionId = cookies().get(lucia.sessionCookieName)?.value ?? null;
		if (!sessionId) {
			return {
				user: null,
				session: null
			};
		}

		const result = await lucia.validateSession(sessionId);
		// next.js throws when you attempt to set cookie when rendering page
		try {
			if (result.session && result.session.fresh) {
				const sessionCookie = lucia.createSessionCookie(result.session.id);
				cookies().set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
			}
			if (!result.session) {
				const sessionCookie = lucia.createBlankSessionCookie();
				cookies().set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
			}
		} catch {}
		return result;
	}
);