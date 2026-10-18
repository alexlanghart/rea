import { lstat, realpath } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { z } from "zod";

import type { AnalysisOperation } from "../application/AnalysisProvider.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisUnsupportedTargetError } from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";
import { ghidraFileFailure } from "./GhidraFileArtifacts.js";

/** Archive format committed by this adapter. */
export const GHIDRA_PROGRAM_ARCHIVE_FORMAT = "rea-ghidra-program-archive-v1";
/** Program-information option that binds an archive to its analysis key. */
export const GHIDRA_PROGRAM_ARCHIVE_KEY_OPTION = "REA program archive key";

const digest = z.string().regex(/^[a-f0-9]{64}$/u);

/**
 * A caller-selected archive of an analyzed Ghidra program, committed into the
 * analysis profile before launch. `key` is the digest of the profile the
 * archive was (or will be) analyzed under, before this commitment was added;
 * together with the target digest it names the archive file.
 */
export const ghidraProgramArchiveCommitmentSchema = z.strictObject({
  format: z.literal(GHIDRA_PROGRAM_ARCHIVE_FORMAT),
  mode: z.enum(["create", "load"]),
  directory: z
    .string()
    .refine(isAbsolute, "Archive directory must be absolute"),
  path: z.string().refine(isAbsolute, "Archive path must be absolute"),
  target_sha256: digest,
  key: digest,
});
export type GhidraProgramArchiveCommitment = z.infer<
  typeof ghidraProgramArchiveCommitmentSchema
>;

/** Archive file name for one target analyzed under one profile. */
export const ghidraProgramArchiveName = (
  targetSha256: string,
  key: string,
): string => `${targetSha256}-${key}.gzf`;

const isMissing = (cause: unknown): boolean =>
  cause instanceof Error && "code" in cause && cause.code === "ENOENT";

/**
 * Select the archive for this target and profile. An existing regular file is
 * loaded instead of re-running import and auto-analysis; otherwise the session
 * analyzes normally and saves the archive before serving.
 */
export const resolveGhidraProgramArchive = async (
  configured: string | undefined,
  targetSha256: string,
  key: string,
  platform: NodeJS.Platform,
  targetPath: string,
): Promise<
  Result<GhidraProgramArchiveCommitment | undefined, AnalysisError>
> => {
  if (configured === undefined) return ok(undefined);
  if (platform === "win32")
    return err(
      new AnalysisUnsupportedTargetError(
        "resolve_analysis_profile",
        targetPath,
        "REA_GHIDRA_PROGRAM_ARCHIVE_DIR is not supported by Windows Ghidra P0.",
      ),
    );
  let directory: string;
  try {
    directory = await realpath(configured);
    if (!(await lstat(directory)).isDirectory())
      throw Object.assign(new Error(`Not a directory: ${directory}`), {
        code: "ENOTDIR",
      });
  } catch (cause: unknown) {
    return err(
      ghidraFileFailure(cause, "resolve_analysis_profile", {
        setting: "REA_GHIDRA_PROGRAM_ARCHIVE_DIR",
        path: configured,
      }),
    );
  }
  const path = join(directory, ghidraProgramArchiveName(targetSha256, key));
  let mode: GhidraProgramArchiveCommitment["mode"];
  try {
    const stats = await lstat(path);
    if (!stats.isFile())
      return err(
        new ProviderAdapterError("ghidra", "resolve_analysis_profile", {
          diagnostics: {
            reason:
              "The Ghidra program archive path exists but is not a regular file.",
            setting: "REA_GHIDRA_PROGRAM_ARCHIVE_DIR",
            path,
          },
        }),
      );
    mode = "load";
  } catch (cause: unknown) {
    if (!isMissing(cause))
      return err(
        ghidraFileFailure(cause, "resolve_analysis_profile", {
          setting: "REA_GHIDRA_PROGRAM_ARCHIVE_DIR",
          path,
        }),
      );
    mode = "create";
  }
  return ok({
    format: GHIDRA_PROGRAM_ARCHIVE_FORMAT,
    mode,
    directory,
    path,
    target_sha256: targetSha256,
    key,
  });
};

/** Fail closed when the served program is not bound to the committed archive key. */
export const ghidraProgramArchiveFailure = (
  commitment: GhidraProgramArchiveCommitment | undefined,
  reportedKey: string | undefined,
  operation: AnalysisOperation,
): ProviderAdapterError | undefined => {
  if (commitment === undefined && reportedKey === undefined) return undefined;
  const reason =
    commitment === undefined
      ? "The Ghidra session reported a program archive key that the profile did not commit."
      : reportedKey === undefined
        ? "The Ghidra session did not report the committed program archive key."
        : reportedKey !== commitment.key
          ? "The Ghidra program archive was analyzed under a different profile than the committed one."
          : undefined;
  return reason === undefined
    ? undefined
    : new ProviderAdapterError("ghidra", operation, {
        diagnostics: { reason, path: commitment?.path ?? null },
      });
};

/** Session limitations that disclose archive reuse or creation. */
export const ghidraProgramArchiveLimitations = (
  commitment: GhidraProgramArchiveCommitment | undefined,
  saved?: boolean,
): readonly string[] =>
  commitment === undefined
    ? []
    : commitment.mode === "load"
      ? [
          `Ghidra loaded a previously analyzed program from ${commitment.path} instead of importing and auto-analyzing the target. The archive's executable digest and analysis key matched this target and profile; its analysis was produced by an earlier REA session, not this one.`,
        ]
      : saved === false
        ? [
            `Ghidra analyzed the target, but saving the program archive to ${commitment.path} failed; the next session will analyze the target again.`,
          ]
        : [
            `Ghidra saved the analyzed program to ${commitment.path} before serving; later sessions with the same target and profile load it instead of re-analyzing. Session annotations are not saved to the archive.`,
          ];
