import { redirect } from "next/navigation";
import { headers } from "next/headers";
import { getConfig } from "@/lib/config-store";
import { ConfigProvider } from "@/contexts/config-context";
import { RepoLayout } from "@/components/repo/repo-layout";
import { getServerSession } from "@/lib/session-server";
import { getToken } from "@/lib/token";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import Link from "next/link";
import { buttonVariants } from "@/components/ui/button";

export default async function Layout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ owner: string; repo: string; branch: string; }>;
}) {
  const { owner, repo, branch } = await params;
  const requestHeaders = await headers();
  const session = await getServerSession();
  const user = session?.user;
  const returnTo = requestHeaders.get("x-return-to");
  const signInUrl =
    returnTo && returnTo !== "/sign-in"
      ? `/sign-in?redirect=${encodeURIComponent(returnTo)}`
      : "/sign-in";
  if (!user) return redirect(signInUrl);

  const decodedBranch = decodeURIComponent(branch);

  let config = {
    owner: owner.toLowerCase(),
    repo: repo.toLowerCase(),
    branch: decodedBranch,
    sha: "",
    version: "",
    object: {}
  }
  
  let errorMessage = null;

  let token: string;
  try {
    const tokenResult = await getToken(user, owner, repo);
    token = tokenResult.token;
  } catch (err: any) {
    console.error(`repo_layout.getToken failed for ${owner}/${repo}: ${err?.message}\n${err?.stack}`);
    throw new Error(`repo_layout.getToken: ${err?.message ?? String(err)}`);
  }

  try {
    const syncedConfig = await getConfig(
      owner,
      repo,
      decodedBranch,
      {
        getToken: async () => token,
      },
    );

    if (syncedConfig) {
      config = syncedConfig;
    }
  } catch (error: any) {
    if (error.status === 404) {
      if (error.response?.data?.message === "Not Found") {
        // Let downstream pages (especially /configuration via Entry) handle missing .pages.yml.
      } else {
        // We assume the branch is not valid
        errorMessage = (
          <Empty className="absolute inset-0 border-0 rounded-none">
            <EmptyHeader>
              <EmptyTitle>Branch not found</EmptyTitle>
              <EmptyDescription>{`The branch "${decodedBranch}" could not be found. It may have been removed or renamed.`}</EmptyDescription>
            </EmptyHeader>
            <EmptyContent>
              <Link className={buttonVariants({ variant: "default" })} href={`/${owner}/${repo}`}>
                Open default branch
              </Link>
            </EmptyContent>
          </Empty>
        );
      }
    } else if (error.status === 403) {
      errorMessage = (
        <Empty className="absolute inset-0 border-0 rounded-none">
          <EmptyHeader>
            <EmptyTitle>Access denied</EmptyTitle>
            <EmptyDescription>You do not have permission to access this repository.</EmptyDescription>
          </EmptyHeader>
          <EmptyContent>
            <Link className={buttonVariants({ variant: "default" })} href="/">
              Choose another repository
            </Link>
          </EmptyContent>
        </Empty>
      );
    } else {
      console.error(`repo_layout.config failed for ${owner}/${repo}@${decodedBranch}: status=${error?.status} message=${error?.message}\n${error?.stack}`);
      throw new Error(`repo_layout.config: status=${error?.status} ${error?.message ?? String(error)}`);
    }
  }

  return (
    <ConfigProvider value={config}>
      <RepoLayout>{errorMessage ? errorMessage : children}</RepoLayout>
    </ConfigProvider>
  );
}
