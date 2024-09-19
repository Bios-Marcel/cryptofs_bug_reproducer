import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoFileSystemProvider;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Iterator;
import java.util.concurrent.ThreadLocalRandom;

public class CrptyoFSOnlyMain {
    private static final String ENCRYPTION_ALGO = "AES";
    private static final String HASH_ALGO = "PBKDF2WithHmacSHA256";
    private static final int HASH_LENGTH = 512;

    public static void main(String[] args) throws Exception {
        final SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGO);
        final KeySpec spec = new PBEKeySpec(
                "c5e2b7e7-e969-4fe8-a949-c047ff0175cb".toCharArray(),
                "jlaswfjow3trijklsdgklm13wlktwsklmtg2w3lk".getBytes(StandardCharsets.UTF_8),
                1, HASH_LENGTH);
        final SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ENCRYPTION_ALGO);

        try (final var masterkey = new Masterkey(key.getEncoded())) {
            //create a copy because the key handed over to init() method will be destroyed
            final MasterkeyLoader loader = ignoredUri -> masterkey.copy();
            final CryptoFileSystemProperties fsProps = CryptoFileSystemProperties
                    .cryptoFileSystemProperties()
                    .withKeyLoader(loader)
                    // Both options cause the issue
                    .withCipherCombo(CryptorProvider.Scheme.SIV_GCM)
                    .build();

            final Path pathToVault = Paths.get("./raw");
            if (!Files.exists(Paths.get("./raw/vault.cryptomator"))) {
                Files.createDirectories(pathToVault);
                CryptoFileSystemProvider.initialize(pathToVault, fsProps, URI.create("id"));
            }

            final var cryptoFS = CryptoFileSystemProvider.newFileSystem(pathToVault, fsProps);
            final var dir = cryptoFS.getPath("/files");
            Files.createDirectories(dir);

            final var bytes = new byte[1024 * 1024 * 1024];
            ThreadLocalRandom.current().nextBytes(bytes);

            System.out.println("Reading");
            for (Iterator<Path> it = Files.newDirectoryStream(dir).iterator(); it.hasNext(); ) {
                var file = it.next();
                Files.readAllBytes(file);
            }
            System.out.println("Reading Done");

            System.out.println("Writing");
            for (int i = 0; i < 100; i++) {
                final var file = dir.resolve(String.valueOf(i));
                Files.write(file, bytes);
            }
            System.out.println("Writing Done");

            cryptoFS.close();
        }
    }
}
