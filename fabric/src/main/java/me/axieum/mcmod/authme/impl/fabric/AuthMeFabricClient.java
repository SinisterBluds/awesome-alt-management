package me.axieum.mcmod.authme.impl.fabric;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

import com.mojang.brigadier.arguments.StringArgumentType;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.command.v2.ClientCommandRegistrationCallback;
import net.fabricmc.fabric.api.client.command.v2.ClientCommands;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.client.Minecraft;
import net.minecraft.network.chat.Component;

import me.axieum.mcmod.authme.api.AuthMe;
import me.axieum.mcmod.authme.api.gui.screen.MicrosoftAuthScreen;
import me.axieum.mcmod.authme.api.util.UpdateChecker;

/**
 * Fabric client entry point. Adds {@code /alt <refresh token>} so a token can be pasted without
 * opening the account screens by hand, and checks GitHub once per session for a newer release.
 */
public class AuthMeFabricClient implements ClientModInitializer
{
    /** Ensures the update check runs at most once per game session. */
    private static final AtomicBoolean UPDATE_CHECKED = new AtomicBoolean(false);

    /** Constructs a new Fabric client entry point. */
    public AuthMeFabricClient() {}

    @Override
    public void onInitializeClient()
    {
        ClientCommandRegistrationCallback.EVENT.register((dispatcher, registryAccess) -> dispatcher.register(
            ClientCommands.literal("alt")
                // greedyString keeps !, *, $ etc. intact; refresh tokens contain no spaces
                .then(ClientCommands.argument("token", StringArgumentType.greedyString())
                    .executes(context -> {
                        final String token = StringArgumentType.getString(context, "token");
                        final Minecraft client = Minecraft.getInstance();
                        client.execute(() ->
                            client.setScreenAndShow(new MicrosoftAuthScreen(null, null, token, null)));
                        context.getSource().sendFeedback(Component.literal(
                            "Logging in with the pasted refresh token (minting client auto-detected)..."));
                        return 1;
                    }))
        ));

        // Notify about a newer release on the first world join of the session
        ClientPlayConnectionEvents.JOIN.register((handler, sender, client) -> checkForUpdates(client));
    }

    private static void checkForUpdates(final Minecraft client)
    {
        if (!UPDATE_CHECKED.compareAndSet(false, true)) return;
        final String localVersion = FabricLoader.getInstance()
            .getModContainer(AuthMe.MOD_ID)
            .map(container -> container.getMetadata().getVersion().getFriendlyString())
            .orElse("0.0.0");

        CompletableFuture.runAsync(() -> {
            final String latest = UpdateChecker.fetchLatestTag();
            if (latest == null || !UpdateChecker.isOutdated(localVersion, latest)) return;
            client.execute(() -> {
                if (client.player != null) {
                    client.player.sendSystemMessage(Component.literal(
                        "[Awesome Alt Management] A newer version is available: " + latest));
                }
            });
        });
    }
}
