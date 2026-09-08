/** Tests credential validation during cross-agent OAuth settlement. */
import fs from "node:fs/promises";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { resetFileLockStateForTest } from "../../infra/file-lock.js";
import { resolveOpenAICodexAuthIdentity } from "../../plugin-sdk/provider-openai-chatgpt-auth.js";
import { captureEnv } from "../../test-utils/env.js";
import "./oauth-external-auth-passthrough.test-support.js";
import { getOAuthProviderRuntimeMocks } from "./oauth-common-mocks.test-support.js";
import { isOAuthRefreshFence, isPendingOAuthRefreshFence } from "./oauth-refresh-marker.js";
import {
  OAUTH_AGENT_ENV_KEYS,
  createOAuthMainAgentDir,
  createOAuthTestTempRoot,
  createExpiredOauthStore,
  removeOAuthTestTempRoot,
  resolveApiKeyForProfileInTest,
  resetOAuthProviderRuntimeMocks,
} from "./oauth-test-utils.js";
import { loadPersistedAuthProfileStore, loadPersistedSharedAuthProfileStore } from "./persisted.js";
import { clearRuntimeAuthProfileStoreSnapshots } from "./runtime-snapshots.js";
import { ensureAuthProfileStore, saveAuthProfileStore } from "./store-runtime.js";
import { persistAuthProfileBatch } from "./upsert-with-lock.js";

const {
  refreshProviderOAuthCredentialWithPluginMock,
  formatProviderAuthProfileApiKeyWithPluginMock,
} = getOAuthProviderRuntimeMocks();

function createWorkspaceAccessToken(accountId: string, rotation: string): string {
  const payload = Buffer.from(
    JSON.stringify({
      "https://api.openai.com/auth": { chatgpt_account_id: accountId },
    }),
  ).toString("base64url");
  return `e30.${payload}.${rotation}`;
}

let resolveApiKeyForProfile: typeof import("./oauth.js").resolveApiKeyForProfile;
let resetOAuthRefreshQueuesForTest: typeof import("./oauth.test-support.js").resetOAuthRefreshQueuesForTest;

async function loadOAuthModuleForTest() {
  ({ resolveApiKeyForProfile } = await import("./oauth.js"));
  ({ resetOAuthRefreshQueuesForTest } = await import("./oauth.test-support.js"));
  resetOAuthRefreshQueuesForTest();
}

vi.mock("../../llm/oauth.js", () => ({
  getOAuthApiKey: vi.fn(async () => null),
  getOAuthProviders: () => [{ id: "openai" }],
}));

describe("createOAuthManager settlement credential validation", () => {
  it("validates a claim-derived superseding owner before settling consumed peers", async () => {
    const envSnapshot = captureEnv(OAUTH_AGENT_ENV_KEYS);
    let tempRoot = "";

    try {
      resetFileLockStateForTest();
      resetOAuthProviderRuntimeMocks({
        refreshProviderOAuthCredentialWithPluginMock,
        formatProviderAuthProfileApiKeyWithPluginMock,
      });
      clearRuntimeAuthProfileStoreSnapshots();
      tempRoot = await createOAuthTestTempRoot("openclaw-oauth-relogin-validator-");
      const mainAgentDir = await createOAuthMainAgentDir(tempRoot);
      await loadOAuthModuleForTest();
      const profileId = "openai:default";
      const provider = "openai";
      const original = createExpiredOauthStore({
        profileId,
        provider,
        access: createWorkspaceAccessToken("workspace-a", "original"),
        email: "shared@example.test",
      });
      const peers = await Promise.all(
        Array.from({ length: 2 }, async (_, index) => {
          const agentDir = path.join(tempRoot, "agents", `peer-${index}`, "agent");
          await fs.mkdir(agentDir, { recursive: true });
          saveAuthProfileStore(original, agentDir);
          return agentDir;
        }),
      );

      let finishRefresh: (() => void) | undefined;
      let markStarted: (() => void) | undefined;
      const started = new Promise<void>((resolve) => {
        markStarted = resolve;
      });
      refreshProviderOAuthCredentialWithPluginMock.mockImplementation(async () => {
        markStarted?.();
        await new Promise<void>((resolve) => {
          finishRefresh = resolve;
        });
        return {
          type: "oauth",
          provider,
          access: createWorkspaceAccessToken("workspace-a", "stale-rotation"),
          refresh: "stale-rotation-refresh",
          expires: Date.now() + 60 * 60 * 1000,
          email: "shared@example.test",
        } as never;
      });

      const validatedWorkspaceIds: Array<string | undefined> = [];
      const resolving = resolveApiKeyForProfileInTest(resolveApiKeyForProfile, {
        store: ensureAuthProfileStore(peers[0]),
        profileId,
        agentDir: peers[0],
        validateOAuthCredential: (credential) => {
          const accountId = resolveOpenAICodexAuthIdentity({
            access: credential.access,
          }).accountId;
          validatedWorkspaceIds.push(accountId);
          if (accountId !== "workspace-a") {
            throw new Error("credential owner mismatch");
          }
        },
      });
      await started;
      await persistAuthProfileBatch({
        agentDir: mainAgentDir,
        profiles: [
          {
            profileId,
            credential: {
              type: "oauth",
              provider,
              access: createWorkspaceAccessToken("workspace-b", "relogin"),
              refresh: "relogin-other-workspace-refresh",
              expires: Date.now() + 10 * 60 * 1000,
              email: "shared@example.test",
            },
          },
        ],
        resetFailureState: true,
        allowOAuthGenerationReplacement: true,
      });
      finishRefresh?.();

      await expect(resolving).rejects.toThrow("credential owner mismatch");
      expect(validatedWorkspaceIds.filter((accountId) => accountId === "workspace-b")).toHaveLength(
        1,
      );
      expect(loadPersistedSharedAuthProfileStore(process.env)?.profiles[profileId]).toMatchObject({
        access: createWorkspaceAccessToken("workspace-b", "relogin"),
        refresh: "relogin-other-workspace-refresh",
      });
      for (const agentDir of peers) {
        const peer = loadPersistedAuthProfileStore(agentDir)?.profiles[profileId];
        expect(peer?.type === "oauth" && isOAuthRefreshFence(peer)).toBe(true);
        expect(peer?.type === "oauth" && isPendingOAuthRefreshFence(peer)).toBe(false);
        expect(peer).not.toMatchObject({
          access: createWorkspaceAccessToken("workspace-b", "relogin"),
        });
      }
    } finally {
      envSnapshot.restore();
      resetFileLockStateForTest();
      clearRuntimeAuthProfileStoreSnapshots();
      await removeOAuthTestTempRoot(tempRoot);
    }
  });

  it("does not recover a conflicting owner after provider refresh failure", async () => {
    const envSnapshot = captureEnv(OAUTH_AGENT_ENV_KEYS);
    let tempRoot = "";

    try {
      resetFileLockStateForTest();
      resetOAuthProviderRuntimeMocks({
        refreshProviderOAuthCredentialWithPluginMock,
        formatProviderAuthProfileApiKeyWithPluginMock,
      });
      clearRuntimeAuthProfileStoreSnapshots();
      tempRoot = await createOAuthTestTempRoot("openclaw-oauth-failed-relogin-validator-");
      await createOAuthMainAgentDir(tempRoot);
      await loadOAuthModuleForTest();
      const profileId = "openai:default";
      const provider = "openai";
      const original = createExpiredOauthStore({
        profileId,
        provider,
        access: createWorkspaceAccessToken("workspace-a", "original"),
        email: "shared@example.test",
      });
      const peers = await Promise.all(
        Array.from({ length: 2 }, async (_, index) => {
          const agentDir = path.join(tempRoot, "agents", `peer-${index}`, "agent");
          await fs.mkdir(agentDir, { recursive: true });
          saveAuthProfileStore(original, agentDir);
          return agentDir;
        }),
      );

      let rejectRefresh: ((error: Error) => void) | undefined;
      let markStarted: (() => void) | undefined;
      const started = new Promise<void>((resolve) => {
        markStarted = resolve;
      });
      refreshProviderOAuthCredentialWithPluginMock.mockImplementation(async () => {
        markStarted?.();
        return await new Promise<never>((_, reject) => {
          rejectRefresh = reject;
        });
      });

      const validatedWorkspaceIds: Array<string | undefined> = [];
      const resolving = resolveApiKeyForProfileInTest(resolveApiKeyForProfile, {
        store: ensureAuthProfileStore(peers[0]),
        profileId,
        agentDir: peers[0],
        validateOAuthCredential: (credential) => {
          const accountId = resolveOpenAICodexAuthIdentity({
            access: credential.access,
          }).accountId;
          validatedWorkspaceIds.push(accountId);
          if (accountId !== "workspace-a") {
            throw new Error("credential owner mismatch");
          }
        },
      });
      await started;
      const conflictingOwner = {
        type: "oauth" as const,
        provider,
        access: createWorkspaceAccessToken("workspace-b", "relogin"),
        refresh: "relogin-other-workspace-refresh",
        expires: Date.now() + 60 * 60 * 1000,
        email: "shared@example.test",
      };
      await persistAuthProfileBatch({
        agentDir: peers[0],
        profiles: [{ profileId, credential: conflictingOwner }],
        resetFailureState: true,
        allowOAuthGenerationReplacement: true,
      });
      rejectRefresh?.(new Error("provider refresh failed"));

      await expect(resolving).rejects.toThrow("credential owner mismatch");
      expect(validatedWorkspaceIds.filter((accountId) => accountId === "workspace-b")).toHaveLength(
        1,
      );
      expect(loadPersistedAuthProfileStore(peers[0])?.profiles[profileId]).toEqual(
        conflictingOwner,
      );
      const peer = loadPersistedAuthProfileStore(peers[1])?.profiles[profileId];
      expect(peer?.type === "oauth" && isOAuthRefreshFence(peer)).toBe(true);
      expect(peer?.type === "oauth" && isPendingOAuthRefreshFence(peer)).toBe(false);
    } finally {
      envSnapshot.restore();
      resetFileLockStateForTest();
      clearRuntimeAuthProfileStoreSnapshots();
      await removeOAuthTestTempRoot(tempRoot);
    }
  });
});
