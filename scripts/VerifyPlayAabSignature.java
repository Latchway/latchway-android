import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.CodeSigner;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.CRC32;

/** Fail-closed raw-ZIP and JAR-signature verifier for Android App Bundles. */
public final class VerifyPlayAabSignature {
    private static final long MAX_ARCHIVE_BYTES = 2L * 1024L * 1024L * 1024L;
    private static final long MAX_MANIFEST_BYTES = 64L * 1024L * 1024L;
    private static final int MAX_ENTRIES = 100_000;
    private static final int LOCAL_HEADER_SIGNATURE = 0x04034b50;
    private static final int CENTRAL_HEADER_SIGNATURE = 0x02014b50;
    private static final int DATA_DESCRIPTOR_SIGNATURE = 0x08074b50;
    private static final int END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50;
    private static final int EXTENDED_TIMESTAMP_EXTRA_FIELD = 0x5455;
    private static final int UTF8_FLAG = 0x0800;
    private static final int DATA_DESCRIPTOR_FLAG = 0x0008;
    private static final int DEFLATE_OPTION_FLAGS = 0x0006;
    private static final String PAYLOAD_MANIFEST_SCHEMA =
        "latchway.android-aab-presign-payload.v1";
    private static final Pattern SHA256 = Pattern.compile("^[0-9a-f]{64}$");
    private static final Pattern SIGNATURE_CONTROL = Pattern.compile(
        "^META-INF/([A-Z0-9_-]{1,32})\\.(SF|RSA|DSA|EC)$"
    );
    private static final Pattern SIGNATURE_CONTROL_CASE_INSENSITIVE = Pattern.compile(
        "^META-INF/([^/]+)\\.(SF|RSA|DSA|EC)$",
        Pattern.CASE_INSENSITIVE
    );

    private VerifyPlayAabSignature() {}

    public static void main(String[] arguments) {
        try {
            if (arguments.length > 0 && arguments[0].equals("--emit-presign-manifest")) {
                emitPresignManifest(arguments);
            } else {
                verify(arguments);
            }
        } catch (Exception | LinkageError error) {
            System.err.println("Play AAB rejected: " + safeMessage(error));
            System.exit(1);
        }
    }

    private static void emitPresignManifest(String[] arguments) throws Exception {
        if (arguments.length != 3) {
            throw new Rejected(
                "usage: VerifyPlayAabSignature --emit-presign-manifest AAB OUTPUT"
            );
        }
        Path archive = checkedFile(Path.of(arguments[1]), "AAB", MAX_ARCHIVE_BYTES);
        Path output = Path.of(arguments[2]).toAbsolutePath().normalize();
        if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
            throw new Rejected("pre-sign payload manifest output already exists");
        }
        RawZip rawZip = RawZip.read(archive);
        List<PayloadEntry> payload = collectPayload(archive, rawZip, ArchiveState.UNSIGNED);
        byte[] canonical = canonicalPayloadManifest(payload);
        Files.write(output, canonical, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        System.out.println("Emitted canonical pre-sign payload manifest for " + payload.size() + " entries.");
    }

    private static void verify(String[] arguments) throws Exception {
        if (arguments.length != 3) {
            throw new Rejected(
                "usage: VerifyPlayAabSignature AAB EXPECTED_CERTIFICATE_SHA256 PRESIGN_MANIFEST"
            );
        }
        Path archive = checkedFile(Path.of(arguments[0]), "AAB", MAX_ARCHIVE_BYTES);
        String expectedCertificateSha256 = arguments[1];
        if (!SHA256.matcher(expectedCertificateSha256).matches()) {
            throw new Rejected("expected certificate SHA-256 is invalid");
        }
        Path carriedManifest = checkedFile(
            Path.of(arguments[2]),
            "pre-sign payload manifest",
            MAX_MANIFEST_BYTES
        );

        // Raw structure and unsigned-to-signed payload continuity are checked
        // before JarFile is opened with cryptographic verification enabled.
        RawZip rawZip = RawZip.read(archive);
        List<PayloadEntry> payload = collectPayload(archive, rawZip, ArchiveState.SIGNED);
        byte[] expectedPayload = Files.readAllBytes(carriedManifest);
        byte[] observedPayload = canonicalPayloadManifest(payload);
        if (!MessageDigest.isEqual(expectedPayload, observedPayload)) {
            throw new Rejected(
                "signed AAB payload does not match the independently carried pre-sign manifest"
            );
        }

        int verifiedPayloadCount = verifyJarSignatures(
            archive,
            rawZip,
            expectedCertificateSha256
        );
        if (verifiedPayloadCount != payload.size()) {
            throw new Rejected("verified payload count changed between continuity and signature checks");
        }
        System.out.println(
            "Verified raw ZIP structure, pre-sign continuity, and exact Play AAB signature " +
            "coverage for " + verifiedPayloadCount + " payload entries."
        );
    }

    private static Path checkedFile(Path input, String label, long maximumBytes) throws IOException {
        Path path = input.toAbsolutePath().normalize();
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
            throw new Rejected(label + " is not a regular non-symlink file");
        }
        long size = Files.size(path);
        if (size <= 0 || size > maximumBytes) {
            throw new Rejected(label + " size is outside the reviewed bound");
        }
        return path;
    }

    private static List<PayloadEntry> collectPayload(
        Path archive,
        RawZip rawZip,
        ArchiveState state
    ) throws Exception {
        List<PayloadEntry> payload = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        long expandedBytes = 0;
        try (JarFile jar = new JarFile(archive.toFile(), false)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (!seen.add(name)) {
                    throw new Rejected("JarFile exposed a duplicate ZIP entry name");
                }
                RawEntry raw = rawZip.byName().get(name);
                if (raw == null) {
                    throw new Rejected("JarFile and raw central directory entry names differ");
                }
                raw.requireSameMetadata(entry);
                EntryContent content = readCompletely(
                    jar,
                    entry,
                    MAX_ARCHIVE_BYTES - expandedBytes
                );
                expandedBytes = Math.addExact(expandedBytes, content.size());
                if (content.size() != raw.uncompressedSize() || content.crc32() != raw.crc32()) {
                    throw new Rejected("AAB entry content does not match its raw central metadata");
                }

                EntryKind kind = entryKind(name);
                if (state == ArchiveState.UNSIGNED && kind != EntryKind.PAYLOAD) {
                    throw new Rejected("unsigned AAB already contains JAR signature metadata");
                }
                if (kind == EntryKind.PAYLOAD) {
                    payload.add(new PayloadEntry(raw, content.sha256()));
                }
            }
        }
        if (seen.size() != rawZip.entries().size()) {
            throw new Rejected("JarFile did not expose every physical central directory entry");
        }
        if (payload.isEmpty()) {
            throw new Rejected("AAB contains no payload entries");
        }
        return List.copyOf(payload);
    }

    private static int verifyJarSignatures(
        Path archive,
        RawZip rawZip,
        String expectedCertificateSha256
    ) throws Exception {
        Set<String> signatureFiles = new HashSet<>();
        Set<String> payloadNames = new HashSet<>();
        Set<String> seen = new HashSet<>();
        String signatureBase = null;
        int signatureFileCount = 0;
        int signatureBlockCount = 0;
        int manifestCount = 0;
        int payloadCount = 0;
        long expandedBytes = 0;
        CodeSigner commonSigner = null;

        try (JarFile jar = new JarFile(archive.toFile(), true)) {
            Manifest manifest = jar.getManifest();
            if (manifest == null) {
                throw new Rejected("AAB does not contain a canonical JAR manifest");
            }
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (!seen.add(name) || !rawZip.byName().containsKey(name)) {
                    throw new Rejected("raw ZIP and JarFile entry sets differ during signature verification");
                }

                long bytesRead = readCompletely(
                    jar,
                    entry,
                    MAX_ARCHIVE_BYTES - expandedBytes
                ).size();
                expandedBytes = Math.addExact(expandedBytes, bytesRead);

                if (name.equals("META-INF/MANIFEST.MF")) {
                    manifestCount++;
                    continue;
                }
                Matcher signatureMatcher = SIGNATURE_CONTROL.matcher(name);
                if (signatureMatcher.matches()) {
                    signatureFiles.add(name);
                    String currentBase = signatureMatcher.group(1);
                    if (signatureBase == null) {
                        signatureBase = currentBase;
                    } else if (!signatureBase.equals(currentBase)) {
                        throw new Rejected("AAB contains an additional signer control set");
                    }
                    if (signatureMatcher.group(2).equals("SF")) {
                        signatureFileCount++;
                    } else {
                        signatureBlockCount++;
                    }
                    continue;
                }

                payloadCount++;
                payloadNames.add(name);
                CodeSigner[] signers = entry.getCodeSigners();
                if (signers == null || signers.length != 1) {
                    throw new Rejected("AAB payload entry is unsigned or has an additional signer");
                }
                if (commonSigner == null) {
                    commonSigner = signers[0];
                } else if (!commonSigner.equals(signers[0])) {
                    throw new Rejected("AAB payload entries do not share exactly one common signer");
                }
                String observedCertificateSha256 = leafCertificateSha256(signers[0]);
                if (!MessageDigest.isEqual(
                    observedCertificateSha256.getBytes(StandardCharsets.US_ASCII),
                    expectedCertificateSha256.getBytes(StandardCharsets.US_ASCII)
                )) {
                    throw new Rejected("AAB payload signer does not match the pinned certificate");
                }
            }

            if (seen.size() != rawZip.entries().size()) {
                throw new Rejected("JarFile did not verify every raw ZIP entry");
            }
            if (manifestCount != 1) {
                throw new Rejected("AAB does not contain exactly one canonical JAR manifest");
            }
            if (!payloadNames.equals(manifest.getEntries().keySet())) {
                throw new Rejected("AAB payload entries do not exactly match signed manifest sections");
            }
        } catch (SecurityException error) {
            throw new Rejected("AAB contains a cryptographically invalid signed entry", error);
        }

        if (payloadCount == 0) {
            throw new Rejected("AAB contains no signed payload entries");
        }
        if (signatureFiles.size() != 2 || signatureFileCount != 1 || signatureBlockCount != 1) {
            throw new Rejected("AAB must contain exactly one signer file and one signer block");
        }
        return payloadCount;
    }

    private static EntryKind entryKind(String name) {
        if (name.equals("META-INF/MANIFEST.MF")) {
            return EntryKind.MANIFEST;
        }
        if (name.equalsIgnoreCase("META-INF/MANIFEST.MF")) {
            throw new Rejected("AAB contains non-canonical manifest metadata");
        }
        if (SIGNATURE_CONTROL.matcher(name).matches()) {
            return EntryKind.SIGNATURE_CONTROL;
        }
        if (SIGNATURE_CONTROL_CASE_INSENSITIVE.matcher(name).matches()) {
            throw new Rejected("AAB contains non-canonical signature control metadata");
        }
        if (name.toUpperCase(Locale.ROOT).startsWith("META-INF/SIG-")) {
            throw new Rejected("AAB contains an unexpected JAR signature artifact");
        }
        return EntryKind.PAYLOAD;
    }

    private static byte[] canonicalPayloadManifest(List<PayloadEntry> input) throws IOException {
        List<PayloadEntry> entries = new ArrayList<>(input);
        entries.sort((left, right) -> compareUnsigned(
            left.raw().rawName(),
            right.raw().rawName()
        ));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        writeAscii(output, "schema=" + PAYLOAD_MANIFEST_SCHEMA + "\n");
        writeAscii(output, "sort=raw_name_unsigned_byte_lexicographic\n");
        writeAscii(
            output,
            "path_semantics=strict_utf8_when_flag_0800_else_ascii;nfc=true;case_unique=true\n"
        );
        writeAscii(
            output,
            "fields=path_utf8_base64url\\traw_name_hex\\tcontent_sha256\\tsize\\tversion_needed_hex\\tflags_hex\\tmethod_hex\\tdos_time_hex\\tdos_date_hex\\tmade_by_hex\\tinternal_attributes_hex\\texternal_mode_hex\\textra_hex\n"
        );
        writeAscii(output, "entry_count=" + entries.size() + "\n");
        Base64.Encoder base64 = Base64.getUrlEncoder().withoutPadding();
        for (PayloadEntry entry : entries) {
            RawEntry raw = entry.raw();
            String path = base64.encodeToString(raw.name().getBytes(StandardCharsets.UTF_8));
            String line = path + "\t" + hex(raw.rawName()) + "\t" + entry.sha256() + "\t" +
                raw.uncompressedSize() + "\t" +
                String.format(Locale.ROOT, "%04x", raw.versionNeeded()) + "\t" +
                String.format(Locale.ROOT, "%04x", raw.flags()) + "\t" +
                String.format(Locale.ROOT, "%04x", raw.method()) + "\t" +
                String.format(Locale.ROOT, "%04x", raw.modificationTime()) + "\t" +
                String.format(Locale.ROOT, "%04x", raw.modificationDate()) + "\t" +
                String.format(Locale.ROOT, "%04x", raw.madeBy()) + "\t" +
                String.format(Locale.ROOT, "%04x", raw.internalAttributes()) + "\t" +
                String.format(Locale.ROOT, "%08x", raw.externalAttributes()) + "\t" +
                hex(raw.extra()) + "\n";
            writeAscii(output, line);
            if (output.size() > MAX_MANIFEST_BYTES) {
                throw new Rejected("canonical pre-sign payload manifest exceeds its bound");
            }
        }
        return output.toByteArray();
    }

    private static void writeAscii(ByteArrayOutputStream output, String value) throws IOException {
        output.write(value.getBytes(StandardCharsets.US_ASCII));
    }

    private static int compareUnsigned(byte[] left, byte[] right) {
        int length = Math.min(left.length, right.length);
        for (int index = 0; index < length; index++) {
            int comparison = Integer.compare(Byte.toUnsignedInt(left[index]), Byte.toUnsignedInt(right[index]));
            if (comparison != 0) return comparison;
        }
        return Integer.compare(left.length, right.length);
    }

    private static EntryContent readCompletely(
        JarFile jar,
        JarEntry entry,
        long remaining
    ) throws Exception {
        if (remaining < 0) {
            throw new Rejected("AAB expands beyond the reviewed bound");
        }
        long count = 0;
        byte[] buffer = new byte[64 * 1024];
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        CRC32 crc32 = new CRC32();
        try (InputStream input = jar.getInputStream(entry)) {
            int read;
            while ((read = input.read(buffer)) != -1) {
                count += read;
                if (count > remaining) {
                    throw new Rejected("AAB expands beyond the reviewed bound");
                }
                digest.update(buffer, 0, read);
                crc32.update(buffer, 0, read);
            }
        }
        if (entry.getSize() >= 0 && count != entry.getSize()) {
            throw new Rejected("AAB entry size changed while it was read");
        }
        return new EntryContent(count, crc32.getValue(), hex(digest.digest()));
    }

    private static String leafCertificateSha256(CodeSigner signer) throws Exception {
        List<? extends Certificate> certificates = signer.getSignerCertPath().getCertificates();
        if (certificates.isEmpty() || !(certificates.get(0) instanceof X509Certificate)) {
            throw new Rejected("AAB signer does not contain an X.509 leaf certificate");
        }
        return hex(MessageDigest.getInstance("SHA-256").digest(certificates.get(0).getEncoded()));
    }

    private static String hex(byte[] bytes) {
        StringBuilder value = new StringBuilder(bytes.length * 2);
        for (byte element : bytes) {
            value.append(String.format(Locale.ROOT, "%02x", element & 0xff));
        }
        return value.toString();
    }

    private static void validateName(String name) {
        if (name.isEmpty() || name.startsWith("/") || name.indexOf('\\') >= 0 || name.indexOf('\0') >= 0) {
            throw new Rejected("AAB contains an unsafe ZIP entry name");
        }
        if (name.endsWith("/")) {
            throw new Rejected("AAB contains an unexpected directory entry");
        }
        if (name.codePoints().anyMatch(value -> value < 0x20 || (value >= 0x7f && value <= 0x9f))) {
            throw new Rejected("AAB contains a control character in a ZIP entry name");
        }
        for (String component : name.split("/", -1)) {
            if (component.isEmpty() || component.equals(".") || component.equals("..")) {
                throw new Rejected("AAB contains an unsafe ZIP entry component");
            }
        }
        if (!Normalizer.isNormalized(name, Normalizer.Form.NFC)) {
            throw new Rejected("AAB contains a non-canonical Unicode ZIP entry name");
        }
    }

    private static String decodeName(byte[] rawName, int flags) {
        if ((flags & UTF8_FLAG) == 0) {
            for (byte value : rawName) {
                int element = Byte.toUnsignedInt(value);
                if (element < 0x20 || element > 0x7e) {
                    throw new Rejected("non-UTF-8 ZIP names must be unambiguous ASCII");
                }
            }
            return new String(rawName, StandardCharsets.US_ASCII);
        }
        try {
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(rawName))
                .toString();
        } catch (CharacterCodingException error) {
            throw new Rejected("AAB contains an invalid UTF-8 ZIP entry name", error);
        }
    }

    private static String safeMessage(Throwable error) {
        String message = error.getMessage();
        return message == null || message.isBlank() ? error.getClass().getSimpleName() : message;
    }

    private enum ArchiveState { UNSIGNED, SIGNED }
    private enum EntryKind { MANIFEST, SIGNATURE_CONTROL, PAYLOAD }

    private record EntryContent(long size, long crc32, String sha256) {}
    private record PayloadEntry(RawEntry raw, String sha256) {}

    private record RawEntry(
        byte[] rawName,
        String name,
        int versionNeeded,
        int flags,
        int method,
        int modificationTime,
        int modificationDate,
        long crc32,
        long compressedSize,
        long uncompressedSize,
        int madeBy,
        int internalAttributes,
        long externalAttributes,
        byte[] extra,
        long localHeaderOffset
    ) {
        void requireSameMetadata(JarEntry entry) {
            if (entry.isDirectory() || entry.getMethod() != method || entry.getCrc() != crc32 ||
                entry.getCompressedSize() != compressedSize || entry.getSize() != uncompressedSize) {
                throw new Rejected("JarFile metadata differs from the validated raw central directory");
            }
        }
    }

    private record RawZip(List<RawEntry> entries, Map<String, RawEntry> byName) {
        static RawZip read(Path archive) throws IOException {
            try (FileChannel channel = FileChannel.open(archive, StandardOpenOption.READ)) {
                long archiveSize = channel.size();
                if (archiveSize < 22 || archiveSize > MAX_ARCHIVE_BYTES) {
                    throw new Rejected("AAB size is outside the reviewed ZIP bound");
                }
                long endOffset = archiveSize - 22;
                ByteBuffer end = read(channel, endOffset, 22);
                requireSignature(end, END_OF_CENTRAL_DIRECTORY_SIGNATURE, "end of central directory");
                int disk = unsignedShort(end, 4);
                int centralDisk = unsignedShort(end, 6);
                int entriesOnDisk = unsignedShort(end, 8);
                int entryCount = unsignedShort(end, 10);
                long centralSize = unsignedInt(end, 12);
                long centralOffset = unsignedInt(end, 16);
                int commentLength = unsignedShort(end, 20);
                if (commentLength != 0 || disk != 0 || centralDisk != 0 || entriesOnDisk != entryCount) {
                    throw new Rejected("AAB has trailing data, a ZIP comment, or spans multiple disks");
                }
                if (entryCount == 0 || entryCount > MAX_ENTRIES || entryCount == 0xffff ||
                    centralSize == 0xffffffffL || centralOffset == 0xffffffffL) {
                    throw new Rejected("ZIP64 and empty or oversized AAB entry sets are unsupported");
                }
                if (Math.addExact(centralOffset, centralSize) != endOffset) {
                    throw new Rejected("central directory is not the exact trailing ZIP structure");
                }

                List<RawEntry> entries = new ArrayList<>(entryCount);
                Map<String, RawEntry> byName = new HashMap<>();
                Set<String> foldedNames = new HashSet<>();
                Set<String> normalizedNames = new HashSet<>();
                long expandedBytes = 0;
                long position = centralOffset;
                for (int index = 0; index < entryCount; index++) {
                    ByteBuffer central = read(channel, position, 46);
                    requireSignature(central, CENTRAL_HEADER_SIGNATURE, "central directory entry");
                    int madeBy = unsignedShort(central, 4);
                    int needed = unsignedShort(central, 6);
                    int flags = unsignedShort(central, 8);
                    int method = unsignedShort(central, 10);
                    int modificationTime = unsignedShort(central, 12);
                    int modificationDate = unsignedShort(central, 14);
                    long crc32 = unsignedInt(central, 16);
                    long compressedSize = unsignedInt(central, 20);
                    long uncompressedSize = unsignedInt(central, 24);
                    int nameLength = unsignedShort(central, 28);
                    int extraLength = unsignedShort(central, 30);
                    int entryCommentLength = unsignedShort(central, 32);
                    int entryDisk = unsignedShort(central, 34);
                    int internalAttributes = unsignedShort(central, 36);
                    long externalAttributes = unsignedInt(central, 38);
                    long localOffset = unsignedInt(central, 42);
                    if (needed > 20 || compressedSize == 0xffffffffL ||
                        uncompressedSize == 0xffffffffL || localOffset == 0xffffffffL) {
                        throw new Rejected("ZIP64 or a post-ZIP-2.0 feature is unsupported");
                    }
                    validateFlagsAndMethod(flags, method);
                    validateVersionNeeded(needed, flags, method);
                    if (nameLength == 0 || entryCommentLength != 0 || entryDisk != 0) {
                        throw new Rejected("central directory entry metadata is ambiguous");
                    }
                    if (internalAttributes != 0) {
                        throw new Rejected("ZIP internal file attributes are unsupported");
                    }
                    long variableOffset = Math.addExact(position, 46);
                    byte[] rawName = bytes(channel, variableOffset, nameLength);
                    byte[] extra = bytes(channel, Math.addExact(variableOffset, nameLength), extraLength);
                    validateExtraFields(extra);
                    String name = decodeName(rawName, flags);
                    validateName(name);
                    if (byName.containsKey(name)) {
                        throw new Rejected("AAB contains duplicate ZIP entry names");
                    }
                    if (!foldedNames.add(name.toLowerCase(Locale.ROOT))) {
                        throw new Rejected("AAB contains case-ambiguous ZIP entry names");
                    }
                    String normalized = Normalizer.normalize(name, Normalizer.Form.NFC)
                        .toLowerCase(Locale.ROOT);
                    if (!normalizedNames.add(normalized)) {
                        throw new Rejected("AAB contains Unicode-normalization-ambiguous ZIP entry names");
                    }
                    validateExternalAttributes(madeBy, externalAttributes);
                    expandedBytes = Math.addExact(expandedBytes, uncompressedSize);
                    if (expandedBytes > MAX_ARCHIVE_BYTES) {
                        throw new Rejected("AAB expands beyond the reviewed bound");
                    }
                    RawEntry entry = new RawEntry(
                        rawName,
                        name,
                        needed,
                        flags,
                        method,
                        modificationTime,
                        modificationDate,
                        crc32,
                        compressedSize,
                        uncompressedSize,
                        madeBy,
                        internalAttributes,
                        externalAttributes,
                        extra,
                        localOffset
                    );
                    entries.add(entry);
                    byName.put(name, entry);
                    position = Math.addExact(
                        variableOffset,
                        Math.addExact(nameLength, Math.addExact(extraLength, entryCommentLength))
                    );
                }
                if (position != Math.addExact(centralOffset, centralSize)) {
                    throw new Rejected("central directory count and size do not describe the same entries");
                }

                List<RawEntry> localOrder = new ArrayList<>(entries);
                localOrder.sort(Comparator.comparingLong(RawEntry::localHeaderOffset));
                long expectedOffset = 0;
                Set<Long> localOffsets = new HashSet<>();
                for (RawEntry entry : localOrder) {
                    if (!localOffsets.add(entry.localHeaderOffset()) ||
                        entry.localHeaderOffset() != expectedOffset) {
                        throw new Rejected("local ZIP records overlap, have gaps, or contain a prefix");
                    }
                    expectedOffset = validateLocalRecord(channel, entry, centralOffset);
                }
                if (expectedOffset != centralOffset) {
                    throw new Rejected("local ZIP records do not end exactly at the central directory");
                }
                return new RawZip(List.copyOf(entries), Map.copyOf(byName));
            }
        }

        private static long validateLocalRecord(
            FileChannel channel,
            RawEntry entry,
            long centralOffset
        ) throws IOException {
            ByteBuffer local = read(channel, entry.localHeaderOffset(), 30);
            requireSignature(local, LOCAL_HEADER_SIGNATURE, "local file header");
            int needed = unsignedShort(local, 4);
            int flags = unsignedShort(local, 6);
            int method = unsignedShort(local, 8);
            int modificationTime = unsignedShort(local, 10);
            int modificationDate = unsignedShort(local, 12);
            long crc32 = unsignedInt(local, 14);
            long compressedSize = unsignedInt(local, 18);
            long uncompressedSize = unsignedInt(local, 22);
            int nameLength = unsignedShort(local, 26);
            int extraLength = unsignedShort(local, 28);
            if (needed > 20 || needed != entry.versionNeeded() ||
                flags != entry.flags() || method != entry.method() ||
                modificationTime != entry.modificationTime() ||
                modificationDate != entry.modificationDate()) {
                throw new Rejected(
                    "local and central ZIP flags, method, required version, or timestamp differ"
                );
            }
            long variableOffset = Math.addExact(entry.localHeaderOffset(), 30);
            byte[] rawName = bytes(channel, variableOffset, nameLength);
            if (!Arrays.equals(rawName, entry.rawName())) {
                throw new Rejected("local and central ZIP entry names differ");
            }
            byte[] extra = bytes(channel, Math.addExact(variableOffset, nameLength), extraLength);
            validateExtraFields(extra);
            if (!Arrays.equals(extra, entry.extra())) {
                throw new Rejected("local and central ZIP extra fields differ");
            }
            long dataOffset = Math.addExact(variableOffset, Math.addExact(nameLength, extraLength));
            long dataEnd = Math.addExact(dataOffset, entry.compressedSize());
            long recordEnd;
            if ((flags & DATA_DESCRIPTOR_FLAG) != 0) {
                boolean zeroLocal = crc32 == 0 && compressedSize == 0 && uncompressedSize == 0;
                boolean exactLocal = crc32 == entry.crc32() &&
                    compressedSize == entry.compressedSize() &&
                    uncompressedSize == entry.uncompressedSize();
                if (!zeroLocal && !exactLocal) {
                    throw new Rejected("data-descriptor local sizes are neither zero nor exact");
                }
                ByteBuffer descriptor = read(channel, dataEnd, 16);
                requireSignature(descriptor, DATA_DESCRIPTOR_SIGNATURE, "data descriptor");
                if (unsignedInt(descriptor, 4) != entry.crc32() ||
                    unsignedInt(descriptor, 8) != entry.compressedSize() ||
                    unsignedInt(descriptor, 12) != entry.uncompressedSize()) {
                    throw new Rejected("data descriptor does not exactly match the central entry");
                }
                recordEnd = Math.addExact(dataEnd, 16);
            } else {
                if (crc32 != entry.crc32() || compressedSize != entry.compressedSize() ||
                    uncompressedSize != entry.uncompressedSize()) {
                    throw new Rejected("local and central ZIP CRC or sizes differ");
                }
                recordEnd = dataEnd;
            }
            if (recordEnd > centralOffset) {
                throw new Rejected("local ZIP entry overlaps the central directory");
            }
            return recordEnd;
        }

        private static void validateFlagsAndMethod(int flags, int method) {
            int allowed = UTF8_FLAG | DATA_DESCRIPTOR_FLAG | DEFLATE_OPTION_FLAGS;
            if ((flags & ~allowed) != 0) {
                throw new Rejected("ZIP entry uses encryption or an unsupported general-purpose flag");
            }
            if (method != JarEntry.STORED && method != JarEntry.DEFLATED) {
                throw new Rejected("ZIP entry uses an unsupported compression method");
            }
            if (method != JarEntry.DEFLATED && (flags & DEFLATE_OPTION_FLAGS) != 0) {
                throw new Rejected("stored ZIP entry declares deflate option flags");
            }
        }

        private static void validateVersionNeeded(int needed, int flags, int method) {
            int expected = method == JarEntry.DEFLATED ||
                (flags & DATA_DESCRIPTOR_FLAG) != 0 ? 20 : 10;
            if (needed != expected) {
                throw new Rejected("ZIP entry declares a non-canonical required version");
            }
        }

        private static void validateExternalAttributes(int madeBy, long attributes) {
            int host = (madeBy >>> 8) & 0xff;
            int unixMode = (int) ((attributes >>> 16) & 0xffff);
            int fileType = unixMode & 0170000;
            int specialMode = unixMode & 07000;
            int dosAttributes = (int) (attributes & 0xff);
            if ((dosAttributes & (0x08 | 0x10)) != 0 ||
                specialMode != 0 ||
                (host != 0 && host != 3) ||
                (host == 0 && unixMode != 0) ||
                (host == 3 && fileType != 0100000)) {
                throw new Rejected("ZIP entry has an unsafe non-regular external mode");
            }
        }

        private static void validateExtraFields(byte[] bytes) {
            int position = 0;
            int fieldCount = 0;
            while (position < bytes.length) {
                if (bytes.length - position < 4) {
                    throw new Rejected("ZIP extra field framing is truncated");
                }
                int identifier = Byte.toUnsignedInt(bytes[position]) |
                    (Byte.toUnsignedInt(bytes[position + 1]) << 8);
                int size = Byte.toUnsignedInt(bytes[position + 2]) |
                    (Byte.toUnsignedInt(bytes[position + 3]) << 8);
                position += 4;
                if (size > bytes.length - position) {
                    throw new Rejected("ZIP extra field length is invalid");
                }
                fieldCount++;
                if (fieldCount != 1 || identifier != EXTENDED_TIMESTAMP_EXTRA_FIELD || size != 5 ||
                    Byte.toUnsignedInt(bytes[position]) != 0x01) {
                    throw new Rejected(
                        "only one canonical mtime-only extended-timestamp ZIP extra field is supported"
                    );
                }
                position += size;
            }
        }

        private static ByteBuffer read(FileChannel channel, long offset, int length) throws IOException {
            if (offset < 0 || length < 0 || Math.addExact(offset, length) > channel.size()) {
                throw new Rejected("ZIP structure points outside the archive");
            }
            ByteBuffer buffer = ByteBuffer.allocate(length).order(ByteOrder.LITTLE_ENDIAN);
            while (buffer.hasRemaining()) {
                int read = channel.read(buffer, Math.addExact(offset, buffer.position()));
                if (read < 0) throw new Rejected("ZIP structure ended unexpectedly");
                if (read == 0) continue;
            }
            buffer.flip();
            return buffer;
        }

        private static byte[] bytes(FileChannel channel, long offset, int length) throws IOException {
            ByteBuffer buffer = read(channel, offset, length);
            byte[] value = new byte[length];
            buffer.get(value);
            return value;
        }

        private static void requireSignature(ByteBuffer buffer, int expected, String label) {
            if (buffer.getInt(0) != expected) {
                throw new Rejected("invalid " + label + " signature");
            }
        }

        private static int unsignedShort(ByteBuffer buffer, int offset) {
            return Short.toUnsignedInt(buffer.getShort(offset));
        }

        private static long unsignedInt(ByteBuffer buffer, int offset) {
            return Integer.toUnsignedLong(buffer.getInt(offset));
        }
    }

    private static final class Rejected extends RuntimeException {
        Rejected(String message) {
            super(message);
        }

        Rejected(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
