package me.axieum.mcmod.authme.api.gui.screen;

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import me.axieum.mcmod.authme.config.Config;
import me.axieum.mcmod.authme.config.PlayerIdentifier;
import me.axieum.mcmod.authme.config.SecretsStorage;
import org.apache.http.conn.ConnectTimeoutException;

import net.minecraft.ChatFormatting;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.StringWidget;
import net.minecraft.client.gui.components.toasts.SystemToast;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;

import me.axieum.mcmod.authme.api.util.MicrosoftUtils;
import me.axieum.mcmod.authme.api.util.MicrosoftUtils.MicrosoftPrompt;
import me.axieum.mcmod.authme.api.util.SessionUtils;

import static me.axieum.mcmod.authme.api.AuthMe.LOGGER;

/**
 * A screen for handling user authentication via Microsoft.
 */
public class MicrosoftAuthScreen extends AuthScreen
{
    // The executor to run the login task on
    private ExecutorService executor = null;
    // The completable future for all Microsoft login tasks
    private CompletableFuture<Void> task = null;
    // The current progress/status of the login task
    private StringWidget statusWidget = null;
    // True if Microsoft should prompt to select an account
    private final boolean selectAccount;
    // True if we should use a refresh token
    private final boolean useRefreshToken;
    // refresh token is useRefreshToken is true
    private final String refreshToken;
    // The OAuth client that minted refreshToken, or null to auto-detect
    private final String knownClientId;

    /**
     * Constructs a new authentication via Microsoft screen.
     *
     * @param parentScreen  parent (or last) screen that opened this screen
     * @param successScreen screen to be returned to after a successful login
     * @param selectAccount true if Microsoft should prompt to select an account
     */
    public MicrosoftAuthScreen(Screen parentScreen, Screen successScreen, boolean selectAccount)
    {
        super(Component.translatable("gui.authme.microsoft.title"), parentScreen, successScreen);
        this.selectAccount = selectAccount;
        this.closeOnSuccess = true;
        this.useRefreshToken = false;

        this.refreshToken = "";
        this.knownClientId = null;
    }

    /**
     * Constructs a useRefreshToken = true MicrosoftAuthScreen.
     * @param parentScreen  parent (or last) screen that opened this screen
     * @param successScreen screen to be returned to after a successful login
     * @param refreshToken the refresh token
     */
    public MicrosoftAuthScreen(Screen parentScreen, Screen successScreen, String refreshToken)
    {
        this(parentScreen, successScreen, refreshToken, null);
    }

    /**
     * Constructs a useRefreshToken = true MicrosoftAuthScreen with a known minting client.
     *
     * @param parentScreen  parent (or last) screen that opened this screen
     * @param successScreen screen to be returned to after a successful login
     * @param refreshToken  the refresh token
     * @param knownClientId the OAuth client that minted the token, or null to auto-detect
     */
    public MicrosoftAuthScreen(Screen parentScreen, Screen successScreen, String refreshToken, String knownClientId)
    {
        super(Component.translatable("gui.authme.microsoft.title"), parentScreen, successScreen);
        this.selectAccount = false;
        this.closeOnSuccess = true;
        this.useRefreshToken = true;

        this.refreshToken = refreshToken;
        this.knownClientId = knownClientId;
    }

    @Override
    protected void init()
    {
        super.init();
        assert minecraft != null;

        if (!SecretsStorage.isPassPhraseSet() &&
                Config.LoginMethods.Microsoft.encryptRefreshTokens) {
            minecraft.setScreenAndShow(new RequestPassPhraseScreen(this));
            return;
        }

        AtomicReference<String> refreshToken = new AtomicReference<>(MicrosoftUtils.NO_REFRESH_TOKEN);

        // Add a title
        StringWidget titleWidget = addRenderableWidget(new StringWidget(title.copy().withColor(0xffffff), font));
        AuthScreen.centerPosition(titleWidget, this, 0, -20);

        // Add a status message
        statusWidget = addRenderableWidget(new StringWidget(title.copy().withColor(0xdddddd), font));
        AuthScreen.centerPosition(statusWidget, this, 0, 15);

        // Add a cancel button to abort the task
        final Button cancelBtn;
        addRenderableWidget(
            cancelBtn = Button.builder(
                Component.translatable("gui.cancel"),
                button -> onClose()
            ).bounds(
                width / 2 - 50, height / 2 + 22, 100, 20
            ).build()
        );

        // Prevent the task from starting several times
        if (task != null) return;

        // Set the initial progress/status of the login task
        Minecraft client = Minecraft.getInstance();
        updateStatusWidget(client, "gui.authme.microsoft.status.checkBrowser");

        // Prepare a new executor thread to run the login task on
        executor = Executors.newSingleThreadExecutor();

        // The client that accepted the refresh token, persisted with the account
        final AtomicReference<MicrosoftUtils.RefreshResult> resolved = new AtomicReference<>();

        // Stage 1: obtain an MSA access token - from a browser auth code, or by exchanging a
        // pasted refresh token with the client that minted it (auto-detected).
        final CompletableFuture<String> xboxAccessTokenStage;
        if (!useRefreshToken) {
            xboxAccessTokenStage = MicrosoftUtils
                    // Acquire a Microsoft auth code
                    .acquireMSAuthCode(
                            success -> Component.translatable("gui.authme.microsoft.browser").getString(),
                            executor,
                            selectAccount ? MicrosoftPrompt.SELECT_ACCOUNT : null
                    )
                    // Exchange the Microsoft auth code for an access token
                    .thenComposeAsync(msAuthCode -> {
                        updateStatusWidget(client, "gui.authme.microsoft.status.msAccessToken");
                        return MicrosoftUtils.acquireMSAccessRefreshToken(msAuthCode, false, executor);
                    })
                    // Exchange the Microsoft access token for an Xbox access token
                    .thenComposeAsync(msAccessRefreshPair -> {
                        refreshToken.set(msAccessRefreshPair.getValue());
                        resolved.set(new MicrosoftUtils.RefreshResult(
                                msAccessRefreshPair.getKey(), msAccessRefreshPair.getValue(),
                                "d", Config.LoginMethods.Microsoft.clientId, "Microsoft"));
                        updateStatusWidget(client, "gui.authme.microsoft.status.xboxAccessToken");
                        return MicrosoftUtils.acquireXboxAccessToken(msAccessRefreshPair.getKey(), "d=", executor);
                    });
        } else {
            xboxAccessTokenStage = MicrosoftUtils
                    // Exchange the refresh token with the minting client
                    .refreshMsaTokenAuto(this.refreshToken, this.knownClientId, executor)
                    .thenComposeAsync(result -> {
                        refreshToken.set(result.refreshToken());
                        resolved.set(result);
                        updateStatusWidget(client, "gui.authme.microsoft.status.xboxAccessToken");
                        return MicrosoftUtils.acquireXboxAccessToken(
                                result.accessToken(), result.tokenType() + "=", executor);
                    });
        }

        // Stages 2-5: XSTS -> Minecraft access token -> profile -> apply the session
        task = xboxAccessTokenStage
            // Exchange the Xbox access token for an XSTS token
            .thenComposeAsync(xboxAccessToken -> {
                updateStatusWidget(client, "gui.authme.microsoft.status.xboxXstsToken");
                return MicrosoftUtils.acquireXboxXstsToken(xboxAccessToken, executor);
            })

            // Exchange the Xbox XSTS token for a Minecraft access token
            .thenComposeAsync(xboxXstsData -> {
                updateStatusWidget(client, "gui.authme.microsoft.status.mcAccessToken");
                return MicrosoftUtils.acquireMCAccessToken(
                    xboxXstsData.get("Token"), xboxXstsData.get("uhs"), executor
                );
            })

            // Build a new Minecraft session with the Minecraft access token
            .thenComposeAsync(mcToken -> {
                updateStatusWidget(client, "gui.authme.microsoft.status.mcProfile");
                return MicrosoftUtils.login(mcToken, executor);
            })

            // Update the game session and greet the player
            .thenAccept(user -> {
                if (!Objects.equals(refreshToken.get(), MicrosoftUtils.NO_REFRESH_TOKEN)) {
                    String username = user.getName();
                    String uuid = user.getProfileId().toString();
                    final MicrosoftUtils.RefreshResult result = resolved.get();
                    final String clientId = result != null ? result.clientId() : null;

                    Optional<PlayerIdentifier> optionalIdentifier =
                            SecretsStorage.playerRefreshTokenPairs
                                    .stream()
                                    .filter(identifier -> Objects.equals(identifier.uuid(), uuid)).findFirst();
                    if (optionalIdentifier.isPresent())
                        SecretsStorage.playerRefreshTokenPairs.remove(optionalIdentifier.orElseThrow());

                    SecretsStorage
                            .playerRefreshTokenPairs
                            .add(new PlayerIdentifier(username, uuid, refreshToken.get(), clientId));
                }
                // Apply the new session
                SessionUtils.setUser(user);
                // Add a toast that greets the player
                SystemToast.add(
                    minecraft.gui.toastManager(), SystemToast.SystemToastId.PERIODIC_NOTIFICATION,
                    Component.translatable("gui.authme.toast.greeting", Component.literal(user.getName())), null
                );
                // Mark the task as successful, in turn closing the screen
                LOGGER.info("Successfully logged in via Microsoft!");
                success = true;
            })

            // On any exception, update the status and cancel button
            .exceptionally(error -> {
                final String key;
                if (error.getCause() instanceof ConnectTimeoutException) {
                    key = "gui.authme.error.timeout";
                } else if ("NOT_FOUND: Not Found".equals(error.getCause().getMessage())) {
                    key = "gui.authme.error.notPurchased";
                } else {
                    LOGGER.error("Could not login via Microsoft!", error);
                    key = "gui.authme.error.generic";
                }
                client.execute(() -> {
                    statusWidget.setMessage(Component.translatable(key).withStyle(ChatFormatting.RED));
                    AuthScreen.centerPosition(statusWidget, this, 0, 15);
                    cancelBtn.setMessage(Component.translatable("gui.back"));
                });
                return null; // return a default value
            });
    }

    private void updateStatusWidget(Minecraft client, String translatableKey)
    {
        client.execute(() -> {
            statusWidget.setMessage(Component.translatable(translatableKey));
            AuthScreen.centerPosition(statusWidget, this, 0, 15);
        });
    }

    @Override
    public void onClose()
    {
        // Cancel the login task if still running
        if (task != null && !task.isDone()) {
            task.cancel(true);
            executor.shutdownNow();
        }

        // Cascade the closing
        super.onClose();
    }
}
