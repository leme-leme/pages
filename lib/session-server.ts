import { cache } from "react";
import { headers } from "next/headers";
import { auth } from "@/lib/auth";
import { lookupApiTokenByRaw, getUserForToken } from "@/lib/api-tokens";

// vinext's headers() returns a Proxy whose target is the immutable
// request.headers Headers instance. Better Auth (and other libs) call
// `new Headers(input)` on whatever we hand them, and workerd's Headers
// constructor reads internal slots from `input` when it sees `input
// instanceof Headers`. Those slots live on the Proxy target, not the
// Proxy itself, which surfaces as a TypeError: Illegal invocation. We
// materialise a plain Headers before passing it across that boundary.
const materializeHeaders = async () => {
  const proxied = await headers();
  const real = new Headers();
  proxied.forEach((value, key) => real.append(key, value));
  return real;
};

const getServerSession = cache(async () => {
  return auth.api.getSession({
    headers: await materializeHeaders(),
  });
});

const requireApiUserSession = async () => {
  const headerList = await materializeHeaders();
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

export { getServerSession, requireApiUserSession, materializeHeaders };
