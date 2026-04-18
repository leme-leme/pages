import { redirect } from "next/navigation";
import { createOctokitInstance } from "@/lib/utils/octokit";
import { getAuth } from "@/lib/auth";
import { getToken } from "@/lib/token";
import { configVersion, parseConfig, normalizeConfig } from "@/lib/config";
import { getConfig, saveConfig, updateConfig } from "@/lib/utils/config";
import { ConfigProvider } from "@/contexts/config-context";
import { RepoLayout } from "@/components/repo/repo-layout";
import { EmptyCreate } from "@/components/empty-create";
import { Message } from "@/components/message";

export default async function Layout({
  children,
  params: { owner, repo, branch },
}: {
  children: React.ReactNode;
  params: { owner: string; repo: string; branch: string; };
}) {
  const { session, user } = await getAuth();
  if (!session) return redirect("/sign-in");

  let token: string;
  try {
    const t = await getToken(user, owner, repo);
    if (!t) throw new Error("Token not found");
    token = t;
  } catch (err: any) {
    console.error(`repo_layout getToken failed for ${owner}/${repo}: ${err?.message}\n${err?.stack}`);
    throw new Error(`repo_layout.getToken: ${err?.message ?? String(err)}`);
  }

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
  
  // We try to retrieve the config file (.pages.yml)
  try {
    const octokit = createOctokitInstance(token);
    const response = await octokit.rest.repos.getContent({
      owner: owner,
      repo: repo,
      path: ".pages.yml",
      ref: decodedBranch,
      headers: { Accept: "application/vnd.github.v3+json" },
    });

    if (Array.isArray(response.data)) {
      throw new Error("Expected a file but found a directory");
    } else if (response.data.type !== "file") {
      throw new Error("Invalid response type");
    }

    const savedConfig = await getConfig(owner, repo, decodedBranch);

    // TODO: make it resilient to config not found (e.g. DB down)

    if (savedConfig && savedConfig.sha === response.data.sha && savedConfig.version === configVersion) {
      // Config in DB and up-to-date
      config = savedConfig;
    } else {
      const configFile = Buffer.from(response.data.content, "base64").toString();
      const parsedConfig = parseConfig(configFile);
      const configObject = normalizeConfig(parsedConfig.document.toJSON());
      
      config.sha = response.data.sha;
      config.version = configVersion ?? "0.0";
      config.object = configObject;

      if (!savedConfig) {
        // Config not in DB
        await saveConfig(config);
      } else {
        // Config in DB but outdated (based on sha or version)
        await updateConfig(config);
      }
    }
  } catch (error: any) {
    console.error(`repo_layout config-fetch failed for ${owner}/${repo}@${decodedBranch}: status=${error?.status} message=${error?.message}\n${error?.stack}`);
    if (error.status === 404) {
      if (error.response?.data?.message === "Not Found") {
        errorMessage = (
          <Message
            title="No configuration file"
            description={`You need to add a ".pages.yml" file to this branch.`}
            className="absolute inset-0"
          >
            <EmptyCreate type="settings">Create a configuration file</EmptyCreate>
          </Message>
        );
      } else {
        // We assume the branch is not valid
        errorMessage = (
          <Message
            title="Invalid branch"
            description={`The branch "${decodedBranch}" doesn't exist. It may have been removed or renamed.`}
            className="absolute inset-0"
            href={`/${owner}/${repo}`}
            cta={"Switch to the default branch"}
          />
        );
      }
    } else {
      // Unknown error — surface it rather than silently falling through
      // to a render with empty config (which then blows up in the child).
      throw new Error(`repo_layout.config: status=${error?.status} ${error?.message ?? String(error)}`);
    }
  }

  return (
    <ConfigProvider value={config}>
      <RepoLayout>{errorMessage ? errorMessage : children}</RepoLayout>
    </ConfigProvider>
  );
}