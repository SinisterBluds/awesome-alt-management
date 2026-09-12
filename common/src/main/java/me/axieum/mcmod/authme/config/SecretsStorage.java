package me.axieum.mcmod.authme.config;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;
import me.axieum.mcmod.authme.api.AuthMe;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public class SecretsStorage {
    private static final Logger log = LoggerFactory.getLogger(SecretsStorage.class);

    // TODO: Make this thread-safe.
    public static List<PlayerIdentifier> playerRefreshTokenPairs = new ArrayList<>();

    // This isn't really "good" practice, but for now it's fine.
    private static String passPhrase = "";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final Path FILE_TO_SAVE_TO = Path.of("./config/" + AuthMe.MOD_ID + "_secrets.json");
    private static final Path ENCRYPTION_ERRORS_FILE = Path.of("config",
            "multi_acc_authme_encryption_errors.txt");

    private static final Gson GSON = new Gson();
    private static final String REFRESH_TOKEN_KEY = "refresh_tokens";

    private static final int ITERATIONS = 1_000_000;

    private static final int KEY_LENGTH = 256;
    private static final int AUTHENTICATION_TAG_LENGTH = 128;

    private static final String BASE_ENCRYPTION_ALGORITHM = "AES";
    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final String KEY_DERIVING_ALGORITHM = "PBKDF2WithHmacSHA256";

    private static final int SALT_LENGTH = 32;
    private static final int IV_LENGTH = 12;

    public static void setPassPhrase(String newPassPhrase) {
        passPhrase = newPassPhrase;
    }

    public static boolean isPassPhraseSet() {
        return !passPhrase.isEmpty();
    }

    /**
     * Saves secrets if the passphrase is available, or we don't have to encrypt the refresh tokens.
     *
     * @return Success (true = success, false = failure)
     */
    public static CompletableFuture<Boolean> save() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                if (!isPassPhraseSet() && Config.LoginMethods.Microsoft.encryptRefreshTokens) {
                    throw new RuntimeException("No Passphrase");
                }

                JsonObject root = new JsonObject();
                root.add(REFRESH_TOKEN_KEY, GSON.toJsonTree(playerRefreshTokenPairs));

                String data = root.toString();

                byte[] stringBytes = data.getBytes(StandardCharsets.UTF_8);
                if (Config.LoginMethods.Microsoft.encryptRefreshTokens)
                    stringBytes = encrypt(passPhrase, stringBytes);

                Files.write(FILE_TO_SAVE_TO, stringBytes);
                return true;
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            } catch (GeneralSecurityException e) {
                log.warn("Tried to decrypt/encrypt and something went wrong. " +
                        "This can just be an invalid" +
                        " passphrase (private key derived from the passphrase), e");
                return false;
            }
        }, AuthMe.VIRTUAL_EXECUTOR_SERVICE);
    }

    /**
     * Loads secrets if the passphrase is available, or we don't have to encrypt the refresh tokens.
     *
     * @return Success (true = success, false = failure, if there is no file it is treated as a success)
     */
    public static CompletableFuture<Boolean> load() throws UncheckedIOException {
        return CompletableFuture.supplyAsync(() -> {
            try {
                if (!isPassPhraseSet() && Config.LoginMethods.Microsoft.encryptRefreshTokens) {
                    throw new RuntimeException("No Passphrase");
                }
                if (!Files.exists(FILE_TO_SAVE_TO)) return true;

                byte[] fileData = Files.readAllBytes(FILE_TO_SAVE_TO);
                if (Config.LoginMethods.Microsoft.encryptRefreshTokens) fileData = decrypt(passPhrase, fileData);

                JsonObject root = GSON.fromJson(new String(fileData, StandardCharsets.UTF_8), JsonObject.class);
                JsonElement element = root.get(REFRESH_TOKEN_KEY);

                playerRefreshTokenPairs = GSON.fromJson(element, new TypeToken<
                        ArrayList<PlayerIdentifier>
                        >() {
                }.getType());

                return true;
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            } catch (GeneralSecurityException e) {
                log.warn("Tried to decrypt/encrypt and something went wrong. " +
                        "This can just be an invalid passphrase " +
                        "(private key derived from the passphrase)", e);
                return false;
            }
        }, AuthMe.VIRTUAL_EXECUTOR_SERVICE);
    }

    private static byte[] encrypt(String passPhrase, byte[] decrypted) throws NoSuchAlgorithmException,
            NoSuchPaddingException,
            BadPaddingException,
            IllegalBlockSizeException,
            InvalidKeyException {
        try {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);

            char[] passPhraseChars = new char[passPhrase.length()];
            passPhrase.getChars(0, passPhraseChars.length, passPhraseChars, 0);

            byte[] salt = new byte[SALT_LENGTH];
            SECURE_RANDOM.nextBytes(salt);

            byte[] iv = new byte[IV_LENGTH];
            SECURE_RANDOM.nextBytes(iv);

            byte[] ivAndSalt = new byte[salt.length + iv.length];
            System.arraycopy(salt, 0, ivAndSalt, 0, salt.length);
            System.arraycopy(iv, 0, ivAndSalt, salt.length, iv.length);

            GCMParameterSpec gcmSpec = new GCMParameterSpec(AUTHENTICATION_TAG_LENGTH, iv);

            cipher.init(Cipher.ENCRYPT_MODE, deriveKey(passPhraseChars, salt), gcmSpec);

            cipher.updateAAD(ivAndSalt);

            byte[] encrypted = cipher.doFinal(decrypted);
            byte[] result = new byte[encrypted.length + ivAndSalt.length];

            System.arraycopy(ivAndSalt, 0, result, 0, ivAndSalt.length);
            System.arraycopy(encrypted, 0, result, ivAndSalt.length, encrypted.length);

            return result;
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] decrypt(String passPhrase, byte[] encrypted) throws NoSuchPaddingException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException {
        try {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);

            char[] passPhraseChars = new char[passPhrase.length()];
            passPhrase.getChars(0, passPhraseChars.length, passPhraseChars, 0);

            byte[] salt = Arrays.copyOfRange(encrypted, 0, SALT_LENGTH);
            byte[] iv = Arrays.copyOfRange(encrypted, SALT_LENGTH, SALT_LENGTH + IV_LENGTH);

            byte[] ivAndSalt = new byte[salt.length + iv.length];
            System.arraycopy(salt, 0, ivAndSalt, 0, salt.length);
            System.arraycopy(iv, 0, ivAndSalt, salt.length, iv.length);

            GCMParameterSpec gcmSpec = new GCMParameterSpec(AUTHENTICATION_TAG_LENGTH, iv);

            byte[] encryptedData =
                    Arrays.copyOfRange(encrypted,
                            ivAndSalt.length,
                            encrypted.length);

            SecretKey key = deriveKey(passPhraseChars, salt);

            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

            cipher.updateAAD(ivAndSalt);

            return cipher.doFinal(encryptedData);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    private static SecretKey deriveKey(char[] password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVING_ALGORITHM);

            byte[] secretKey = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(secretKey, BASE_ENCRYPTION_ALGORITHM);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
    private SecretsStorage() {};
}