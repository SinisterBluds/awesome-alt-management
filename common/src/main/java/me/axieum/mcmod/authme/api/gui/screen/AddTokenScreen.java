package me.axieum.mcmod.authme.api.gui.screen;

import me.axieum.mcmod.authme.api.util.MicrosoftUtils;
import me.axieum.mcmod.authme.config.Config;
import me.axieum.mcmod.authme.config.SecretsStorage;
import net.minecraft.ChatFormatting;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.components.StringWidget;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;

/**
 * Lets the user paste a Microsoft refresh token (for example one handed out by
 * a web front end or an alt source) and log in with it. The OAuth client that minted
 * the token is auto-detected, so Prism, Lunar, LabyMod, Mojang and other
 * launcher tokens all work without configuration.
 */
public class AddTokenScreen extends Screen
{
    /** The parent (or last) screen that opened this screen. */
    private final Screen parentScreen;
    /** The refresh-token input field. */
    private EditBox tokenField;
    /** The validation/status line. */
    private StringWidget statusWidget;

    /**
     * Constructs a new paste-a-refresh-token screen.
     *
     * @param parentScreen parent (or last) screen that opened this screen
     */
    public AddTokenScreen(Screen parentScreen)
    {
        super(Component.translatable("gui.authme.addtoken.title"));
        this.parentScreen = parentScreen;
    }

    @Override
    protected void init()
    {
        super.init();
        assert minecraft != null;

        // Refresh tokens are saved encrypted, so a pass phrase is required first
        if (!SecretsStorage.isPassPhraseSet() && Config.LoginMethods.Microsoft.encryptRefreshTokens) {
            minecraft.setScreenAndShow(new RequestPassPhraseScreen(this));
            return;
        }

        // Title
        StringWidget titleWidget = addRenderableWidget(new StringWidget(title.copy().withColor(0xffffff), font));
        AuthScreen.centerPosition(titleWidget, this, 0, -46);

        // Hint
        StringWidget hintWidget = addRenderableWidget(new StringWidget(
            Component.translatable("gui.authme.addtoken.hint").withColor(0xa0a0a0), font
        ));
        AuthScreen.centerPosition(hintWidget, this, 0, -28);

        // Token input
        tokenField = addRenderableWidget(new EditBox(
            font, width / 2 - 150, height / 2 - 6, 300, 20,
            Component.translatable("gui.authme.addtoken.field")
        ));
        tokenField.setMaxLength(8192);
        tokenField.setHint(Component.translatable("gui.authme.addtoken.field").withColor(0x808080));

        // Status line
        statusWidget = addRenderableWidget(new StringWidget(Component.empty(), font));
        AuthScreen.centerPosition(statusWidget, this, 0, 22);

        // Add + login
        addRenderableWidget(Button.builder(
            Component.translatable("gui.authme.addtoken.add"), button -> submit()
        ).bounds(width / 2 - 100, height / 2 + 26, 200, 20).build());

        // Back
        addRenderableWidget(Button.builder(
            Component.translatable("gui.back"), button -> onClose()
        ).bounds(width / 2 - 100, height / 2 + 50, 200, 20).build());

        setInitialFocus(tokenField);
    }

    private void submit()
    {
        final String token = MicrosoftUtils.normalizeToken(tokenField.getValue());
        if (token.isBlank()) {
            statusWidget.setMessage(Component.translatable("gui.authme.addtoken.error").withStyle(ChatFormatting.RED));
            AuthScreen.centerPosition(statusWidget, this, 0, 22);
            return;
        }
        assert minecraft != null;
        // knownClientId is unknown for a pasted token; the login screen auto-detects it.
        minecraft.setScreenAndShow(new MicrosoftAuthScreen(this, parentScreen, token, null));
    }

    @Override
    public void onClose()
    {
        if (minecraft != null) minecraft.setScreenAndShow(parentScreen);
    }

    @Override
    public boolean isPauseScreen()
    {
        return false;
    }
}
