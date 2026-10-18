import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseConfig } from "../config/parseConfig.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { silentLogger } from "../logger.js";
import { ghidraProfileInstallationHost as host } from "./GhidraInstallation.fixture.js";
import { ghidraHeadlessArguments } from "./GhidraLauncher.js";
import {
  ghidraProgramArchiveCommitmentSchema,
  ghidraProgramArchiveFailure,
  ghidraProgramArchiveLimitations,
  ghidraProgramArchiveName,
  resolveGhidraProgramArchive,
  type GhidraProgramArchiveCommitment,
} from "./GhidraProgramArchive.js";
import { GhidraProvider } from "./GhidraProvider.js";

const directories: string[] = [];
afterEach(async () => {
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
});
const workspace = async () => {
  const directory = await realpath(
    await mkdtemp(join(tmpdir(), "rea-ghidra-archive-")),
  );
  directories.push(directory);
  return directory;
};

const TARGET = "a".repeat(64);
const KEY = "b".repeat(64);

describe("Ghidra program archive resolution", () => {
  it("is absent without configuration", async () => {
    const resolved = await resolveGhidraProgramArchive(
      undefined,
      TARGET,
      KEY,
      "linux",
      "/fixture.exe",
    );
    expect(resolved).toEqual({ ok: true, value: undefined });
  });

  it("creates an archive named by target and profile digests", async () => {
    const directory = await workspace();
    const resolved = await resolveGhidraProgramArchive(
      directory,
      TARGET,
      KEY,
      "linux",
      "/fixture.exe",
    );
    if (!resolved.ok) throw resolved.error;
    expect(resolved.value).toEqual({
      format: "rea-ghidra-program-archive-v1",
      mode: "create",
      directory,
      path: join(directory, `${TARGET}-${KEY}.gzf`),
      target_sha256: TARGET,
      key: KEY,
    });
  });

  it("loads an existing archive", async () => {
    const directory = await workspace();
    await writeFile(join(directory, ghidraProgramArchiveName(TARGET, KEY)), "");
    const resolved = await resolveGhidraProgramArchive(
      directory,
      TARGET,
      KEY,
      "linux",
      "/fixture.exe",
    );
    if (!resolved.ok) throw resolved.error;
    expect(resolved.value?.mode).toBe("load");
  });

  it("refuses a non-file at the archive path", async () => {
    const directory = await workspace();
    await mkdir(join(directory, ghidraProgramArchiveName(TARGET, KEY)));
    const resolved = await resolveGhidraProgramArchive(
      directory,
      TARGET,
      KEY,
      "linux",
      "/fixture.exe",
    );
    expect(resolved.ok).toBe(false);
  });

  it("refuses a missing directory and Windows hosts", async () => {
    const directory = await workspace();
    for (const [configured, platform] of [
      [join(directory, "missing"), "linux"],
      [directory, "win32"],
    ] as const) {
      const resolved = await resolveGhidraProgramArchive(
        configured,
        TARGET,
        KEY,
        platform,
        "/fixture.exe",
      );
      expect(resolved.ok).toBe(false);
    }
  });

  it("requires an absolute directory", () => {
    expect(parseConfig({ REA_GHIDRA_PROGRAM_ARCHIVE_DIR: "archives" }).ok).toBe(
      false,
    );
  });
});

describe("Ghidra program archive profile", () => {
  const pe: BinaryTarget = {
    path: "/fixture.exe",
    sha256: TARGET,
    kind: "executable",
    format: "pe",
    architecture: "x86",
    availableArchitectures: ["x86"],
    executableRole: "application",
    managed: false,
  };

  it("keys the archive by the profile digest before the archive commitment", async () => {
    const directory = await workspace();
    const plain = parseConfig({ GHIDRA_INSTALL_DIR: "/ghidra" });
    const archived = parseConfig({
      GHIDRA_INSTALL_DIR: "/ghidra",
      REA_GHIDRA_PROGRAM_ARCHIVE_DIR: directory,
    });
    if (!plain.ok) throw plain.error;
    if (!archived.ok) throw archived.error;
    const base = await new GhidraProvider(
      plain.value,
      silentLogger,
      {},
      host,
    ).resolveAnalysisProfile(pe);
    const resolved = await new GhidraProvider(
      archived.value,
      silentLogger,
      {},
      host,
    ).resolveAnalysisProfile(pe);
    if (!base.ok) throw base.error;
    if (!resolved.ok) throw resolved.error;
    const commitment = ghidraProgramArchiveCommitmentSchema.parse(
      resolved.value.profile?.parameters.program_archive,
    );
    expect(commitment.key).toBe(base.value.profile?.digest);
    expect(commitment.mode).toBe("create");
    expect(resolved.value.profile?.digest).not.toBe(base.value.profile?.digest);
  });
});

describe("Ghidra program archive session checks", () => {
  const commitment: GhidraProgramArchiveCommitment = {
    format: "rea-ghidra-program-archive-v1",
    mode: "load",
    directory: "/archives",
    path: `/archives/${TARGET}-${KEY}.gzf`,
    target_sha256: TARGET,
    key: KEY,
  };

  it("accepts the committed key and an absent archive", () => {
    expect(
      ghidraProgramArchiveFailure(commitment, KEY, "xrefs"),
    ).toBeUndefined();
    expect(
      ghidraProgramArchiveFailure(undefined, undefined, "xrefs"),
    ).toBeUndefined();
  });

  it.each([
    ["a missing report", commitment, undefined],
    ["an uncommitted report", undefined, KEY],
    ["a different key", commitment, "c".repeat(64)],
  ])("fails closed on %s", (_label, committed, reported) => {
    expect(
      ghidraProgramArchiveFailure(committed, reported, "xrefs"),
    ).toBeDefined();
  });

  it("discloses loading, saving and a failed save", () => {
    expect(ghidraProgramArchiveLimitations(commitment)[0]).toMatch(
      /loaded a previously analyzed program/u,
    );
    const create = { ...commitment, mode: "create" as const };
    expect(ghidraProgramArchiveLimitations(create, true)[0]).toMatch(
      /saved the analyzed program/u,
    );
    expect(ghidraProgramArchiveLimitations(create, false)[0]).toMatch(
      /saving the program archive .* failed/u,
    );
  });
});

describe("Ghidra program archive launch arguments", () => {
  const base = {
    platform: "linux" as const,
    projectRoot: "/tmp/project",
    targetPath: "/tmp/target.exe",
    bridgeScriptPath: "/package/bridge/ReaGhidraBridge.java",
    descriptorPath: "/tmp/session.json",
    ghidraLogPath: "/tmp/ghidra.log",
    scriptLogPath: "/tmp/script.log",
    seedPath: "/tmp/seeds.tsv",
  };

  it("imports a loaded archive without analysis or preparation scripts", () => {
    const arguments_ = ghidraHeadlessArguments({
      ...base,
      programArchive: { mode: "load", path: "/archives/x.gzf", key: KEY },
    });
    expect(arguments_.slice(0, 5)).toEqual([
      "/tmp/project",
      "rea-project",
      "-import",
      "/archives/x.gzf",
      "-noanalysis",
    ]);
    expect(arguments_).not.toContain("/tmp/target.exe");
    expect(arguments_).not.toContain("-preScript");
    expect(arguments_).toContain("-readOnly");
    expect(arguments_).toContain("-deleteProject");
    expect(arguments_.filter((value) => value === "-postScript")).toHaveLength(
      1,
    );
    expect(arguments_.at(-2)).toBe("/package/bridge/ReaGhidraBridge.java");
  });

  it("saves a created archive after repairs and before the bridge", () => {
    const arguments_ = ghidraHeadlessArguments({
      ...base,
      programArchive: { mode: "create", path: "/archives/x.gzf", key: KEY },
    });
    const save = arguments_.indexOf(
      join("/package/bridge", "ReaGhidraSaveProgramArchive.java"),
    );
    const repair = arguments_.indexOf(
      join("/package/bridge", "ReaGhidraNoReturnFix.java"),
    );
    expect(repair).toBeGreaterThan(0);
    expect(save).toBeGreaterThan(repair);
    expect(arguments_.slice(save + 1, save + 3)).toEqual([
      "/archives/x.gzf",
      KEY,
    ]);
    expect(save).toBeLessThan(
      arguments_.indexOf("/package/bridge/ReaGhidraBridge.java"),
    );
    expect(arguments_).toContain("/tmp/target.exe");
  });

  it("refuses an archive on Windows", () => {
    expect(() =>
      ghidraHeadlessArguments({
        ...base,
        platform: "win32",
        programArchive: { mode: "load", path: "C:\\x.gzf", key: KEY },
      }),
    ).toThrow(/not admitted on Windows/u);
  });
});
