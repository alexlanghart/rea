import ghidra.app.script.GhidraScript;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.program.model.listing.Program;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

/**
 * Save the analyzed program as a packed Ghidra archive after analysis and the
 * post-analysis repairs, before the bridge serves.
 *
 * Arguments: the archive path and the analysis key. The key is stored as a
 * program-information option first, so the archive carries it and the bridge
 * reports it for both this session and later sessions that load the archive.
 * The archive is written in a private directory beside its destination and linked into place without
 * replacing an existing file, so a failed or concurrent save never exposes a
 * partial archive. A save failure leaves the analysis usable; the outcome is
 * stored for the bridge handshake.
 */
public final class ReaGhidraSaveProgramArchive extends GhidraScript {
    static final String KEY_OPTION = "REA program archive key";
    static final String SAVED_OPTION = "REA program archive saved";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("REA archive script requires a path and a key");
        }
        Path target = Path.of(args[0]);
        var info = currentProgram.getOptions(Program.PROGRAM_INFO);
        info.setString(KEY_OPTION, args[1]);
        info.setBoolean(SAVED_OPTION, false);
        // Packing requires no open transaction; GhidraScript wraps run() in one.
        end(true);
        // Pack inside an owner-only directory on the destination's file system,
        // so the archive is never readable by others before its mode is set.
        Path privateDirectory = null;
        Path partial = null;
        boolean saved = false;
        try {
            privateDirectory = Files.createTempDirectory(
                target.getParent(),
                ".rea-archive-",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
            );
            partial = privateDirectory.resolve("program.gzf");
            ((DomainObjectAdapterDB) currentProgram).saveToPackedFile(partial.toFile(), monitor);
            Files.setPosixFilePermissions(partial, PosixFilePermissions.fromString("rw-------"));
            try {
                Files.createLink(target, partial);
                saved = true;
            }
            catch (FileAlreadyExistsException exists) {
                // A concurrent session published the same target and profile first.
                saved = Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS);
            }
        }
        catch (Exception failure) {
            printerr("REA program archive save failed: " + failure);
        }
        finally {
            if (partial != null) Files.deleteIfExists(partial);
            if (privateDirectory != null) Files.deleteIfExists(privateDirectory);
        }
        start();
        info.setBoolean(SAVED_OPTION, saved);
    }
}
