package me.axieum.mcmod.authme.api;

import com.teamresourceful.resourcefulconfig.api.loader.Configurator;
import me.axieum.mcmod.authme.api.gui.screen.UserSelectionScreen;
import me.axieum.mcmod.authme.config.Config;
import me.axieum.mcmod.authme.config.SecretsStorage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Reader;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The multi-platform common mod.
 */
public final class AuthMe
{
    private AuthMe() {}

    /**
     * The mod identifier.
     */
    public static final String MOD_ID = "multiaccauthme";

    /**
     * The mod display name.
     */
    public static final String MOD_NAME = "Awesome Alt Management";

    /**
     * The mod logger.
     */
    public static final Logger LOGGER = LoggerFactory.getLogger(MOD_NAME);

    /**
     * Virtual Thread Executor Service
     */
    public static final ExecutorService VIRTUAL_EXECUTOR_SERVICE = Executors.newVirtualThreadPerTaskExecutor();

    /**
     * The mod configuration.
     */
    public static final Configurator CONFIG = new Configurator(MOD_ID);

    /**
     * The legacy Mojang account migration FAQ link.
     */
    public static final String MOJANG_ACCOUNT_MIGRATION_FAQ_URL = "https://aka.ms/MinecraftPostMigrationFAQ";

    /**
     * Initialises the multi-platform mod.
     */
    public static void init()
    {
        // Register the configuration
        CONFIG.register(Config.class);

        if (!Config.LoginMethods.Microsoft.encryptRefreshTokens) {
            try {
                SecretsStorage.load()
                        .thenAccept((result) -> {
                    if (!result) LOGGER.warn("Couldn't load secrets.");
                });
            } catch (CompletionException e) {
                LOGGER.error("Concurrency error while saving secrets.", e);
            }
        }

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (Config.LoginMethods.Microsoft.encryptRefreshTokens && !SecretsStorage.isPassPhraseSet()) return;
            try {
                if (!SecretsStorage.save().join()) {
                    LOGGER.warn("Couldn't save secrets.");
                }
            } catch (CompletionException e) {
                LOGGER.error("Concurrency error while saving secrets.", e);
            }
        }));
    }
}
