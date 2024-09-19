import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoFileSystemProvider;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.eclipse.store.afs.nio.types.NioFileSystem;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageFoundation;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;
import org.eclipse.store.storage.types.Storage;
import org.eclipse.store.storage.types.StorageLiveFileProvider;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.concurrent.ThreadLocalRandom;

public class EclipseStoreMain {
    public static void main(String[] args) {
        final var storage = createEncryptedStorage();
        // final var storage = createStorage();

        storage.start();

        if (storage.root() == null) {
            storage.setRoot(new StorageRoot());
            storage.storeRoot();
        }
        final StorageRoot root = (StorageRoot) storage.root();

        storage.issueFullGarbageCollection();

        System.out.println(root.a.bytes.size() + "," + root.b.bytes.size() + "," + root.c.bytes.size());

        final var entryTemplate = new byte[1024 * 1024];
        ThreadLocalRandom.current().nextBytes(entryTemplate);

        final var storer = storage.createLazyStorer();

        System.out.println("Storing A");
        for (int i = 1; i < 600; i++) {
            final var newEntry = new byte[entryTemplate.length];
            System.arraycopy(entryTemplate, 0, newEntry, 0, newEntry.length);
            storer.store(newEntry);
            root.a.bytes.add(newEntry);
        }

        System.out.println("Storing B");
        for (int i = 1; i < 600; i++) {
            final var newEntry = new byte[entryTemplate.length];
            System.arraycopy(entryTemplate, 0, newEntry, 0, newEntry.length);
            storer.store(newEntry);
            root.b.bytes.add(newEntry);
        }

        System.out.println("Storing C");
        for (int i = 1; i < 600; i++) {
            final var newEntry = new byte[entryTemplate.length];
            System.arraycopy(entryTemplate, 0, newEntry, 0, newEntry.length);
            storer.store(newEntry);
            root.c.bytes.add(newEntry);
        }

        storer.store(root.a.bytes);
        storer.store(root.b.bytes);
        storer.store(root.c.bytes);
        System.out.println("Stored");

        System.out.println("Committing");
        storer.commit();
        System.out.println("Comitted");

        System.out.println("Closing");
        storage.close();
        System.out.println("Closed");
    }

    private static final String ENCRYPTION_ALGO = "AES";
    private static final String HASH_ALGO = "PBKDF2WithHmacSHA256";
    private static final int HASH_LENGTH = 512;

    private static EmbeddedStorageManager createEncryptedStorage() {
        try {
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

                final Path pathToVault = Paths.get("./db_encrypted");
                if (!Files.exists(Paths.get("./db_encrypted/vault.cryptomator"))) {
                    Files.createDirectories(pathToVault);
                    CryptoFileSystemProvider.initialize(pathToVault, fsProps, URI.create("id"));
                }

                final var cryptoFS = CryptoFileSystemProvider.newFileSystem(pathToVault, fsProps);
                final var nioFSCrypto = NioFileSystem.New(cryptoFS);
                final StorageLiveFileProvider fileProvider = Storage.FileProviderBuilder(nioFSCrypto)
                        .setDirectory(nioFSCrypto.ensureDirectoryPath("/db"))
                        .createFileProvider();

                return EmbeddedStorageFoundation
                        .New()
                        .setConfiguration(
                                org.eclipse.store.storage.types.StorageConfiguration
                                        .Builder()
                                        .setStorageFileProvider(
                                                fileProvider
                                        )
                                        .createConfiguration())
                        .createEmbeddedStorageManager();
            }
        } catch (final InvalidKeySpecException | NoSuchAlgorithmException | IOException exception) {
            throw new RuntimeException(exception);
        }
    }

    private static EmbeddedStorageManager createStorage() {
        final var nioFSCrypto = NioFileSystem.New(FileSystems.getDefault());
        final StorageLiveFileProvider fileProvider = Storage.FileProviderBuilder(nioFSCrypto)
                .setDirectory(nioFSCrypto.ensureDirectoryPath("./db_unencrypted"))
                .createFileProvider();

        return EmbeddedStorageFoundation
                .New()
                .setConfiguration(
                        org.eclipse.store.storage.types.StorageConfiguration
                                .Builder()
                                .setStorageFileProvider(
                                        fileProvider
                                )
                                .createConfiguration())
                .createEmbeddedStorageManager();
    }
}
