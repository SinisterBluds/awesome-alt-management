package me.axieum.mcmod.authme.api.gui.screen;

import me.axieum.mcmod.authme.config.Config;
import me.axieum.mcmod.authme.config.PlayerIdentifier;
import me.axieum.mcmod.authme.config.SecretsStorage;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserSelectionScreen extends Screen {
    private static final Logger LOGGER = LoggerFactory.getLogger(UserSelectionScreen.class);

    private static final int CHAR_SIZE = 15;
    private static final int GAP_BETWEEN_BUTTONS = 5;
    private static final int HEIGHT = 20;

    private final Screen successScreen;

    protected UserSelectionScreen(Screen successScreen) {
        super(Component.translatable("gui.authme.userselect.title"));
        this.successScreen = successScreen;
    }

    @Override
    protected void init() {
        Button lastButton = null;

        if (!SecretsStorage.isPassPhraseSet() &&
                Config.LoginMethods.Microsoft.encryptRefreshTokens) {
            minecraft.setScreenAndShow(new RequestPassPhraseScreen(this));
            return;
        }

        for (int i = 0; i < SecretsStorage.playerRefreshTokenPairs.size(); i++) {
            PlayerIdentifier identifier = SecretsStorage.playerRefreshTokenPairs.get(i);
            // TODO: Images perhaps just a Steve but maybe the player skin head later on
            Button button = new Button.Builder(Component.literal(identifier.username()), (press) -> {
                minecraft.setScreenAndShow(new MicrosoftAuthScreen(this, successScreen, identifier.refreshToken(), identifier.clientId()));
            })
                    .bounds(
                            i + (lastButton == null ? GAP_BETWEEN_BUTTONS : lastButton.getX() + lastButton.getWidth() + GAP_BETWEEN_BUTTONS),
                            0,
                            CHAR_SIZE * identifier.username().length(),
                            HEIGHT
                    ).build();
            addRenderableWidget(button);

            lastButton = button;
        }
    }
}
