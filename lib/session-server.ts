import { cache } from "react";
import { headers } from "next/headers";
import { auth } from "@/lib/auth";
import { lookupApiTokenByRaw, getUserForToken } from "@/lib/api-tokens";

const getServerSession = cache(async () => {
  return auth.api.getSession({
    headers: await headers(),
  });
});

const requireApiUserSession = async () => {
  const headerList = await headers();
  const bearer = headerList.get("authorization");
  if (bearer?.toLowerCase().startsWith("bearer ")) {
    const raw = bearer.slice(7).trim();
    const token = await lookupApiTokenByRaw(raw);
    if (token) {
      const user = await getUserForToken(token);
      if (user) {
        return {
          user: { ...user } as typeof user & { _apiToken?: typeof token },
          apiToken: token,
        };
      }
    }
    return { response: new Response(null, { status: 401 }) };
  }

  const session = await auth.api.getSession({ headers: headerList });
  if (!session?.user) {
    return { response: new Response(null, { status: 401 }) };
  }
  return { user: session.user };
};

export { getServerSession, requireApiUserSession };
