package me.axieum.mcmod.authme.api.gui.screen;

import me.axieum.mcmod.authme.config.SecretsStorage;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;
import net.minecraft.util.CommonColors;
import org.jspecify.annotations.NonNull;

/**
 * Loads the passphrase and loads secrets.
 */
public class RequestPassPhraseScreen extends Screen {
    private static final int PASS_PHRASE_INPUT_CENTER_OFFSET_X = -100;
    private static final int PASS_PHRASE_INPUT_CENTER_OFFSET_Y = -6;

    private static final int PASS_PHRASE_INPUT_SIZE_X = 200;
    private static final int PASS_PHRASE_INPUT_SIZE_Y = 20;

    private static final int LABEL_PHRASE_INPUT_CENTER_OFFSET_X = -200;
    private static final int LABEL_PHRASE_INPUT_CENTER_OFFSET_Y = -20;

    private static final int CONFIRM_BUTTON_CENTER_OFFSET_X = -100;
    private static final int CONFIRM_BUTTON_CENTER_OFFSET_Y = 40;

    private static final int CONFIRM_BUTTON_SIZE_X = 200;
    private static final int CONFIRM_BUTTON_SIZE_Y = 20;

    private final Screen successScreen;
    private Component labelContent = Component.translatable("gui.authme.request_pass_phrase.label.initial");

    public RequestPassPhraseScreen(Screen successScreen) {
        super(
                Component
                        .translatable("gui.authme.request_pass_phrase.title")
                        .withColor(CommonColors.GREEN)
        );
        this.successScreen = successScreen;
    }

    @Override
    protected void init() {
        super.init();

        EditBox input = new EditBox(
                minecraft.font,
                width / 2 + PASS_PHRASE_INPUT_CENTER_OFFSET_X,
                height / 2 + PASS_PHRASE_INPUT_CENTER_OFFSET_Y,
                PASS_PHRASE_INPUT_SIZE_X,
                PASS_PHRASE_INPUT_SIZE_Y,
                Component.translatable("gui.authme.request_pass_phrase.pass_phrase_input")
        );
        Button confirm = new Button.Builder(Component
                .translatable("gui.authme.request_pass_phrase.confirm_button"),
                (button) -> {
                    SecretsStorage.setPassPhrase(input.getValue());
                    labelContent = Component.translatable("gui.authme.request_pass_phrase.label.waiting");

                    SecretsStorage.load()
                            .thenAccept((result) -> {
                        if (result) {
                            minecraft.schedule(() -> {
                                minecraft.setScreenAndShow(successScreen);
                            });
                        } else {
                            minecraft.schedule(() -> {
                                labelContent = Component.translatable("gui.authme.request_pass_phrase.label.wrong");
                                SecretsStorage.setPassPhrase("");
                            });
                        }
                    });
                })
                .bounds(width / 2 + CONFIRM_BUTTON_CENTER_OFFSET_X,
                        height / 2 + CONFIRM_BUTTON_CENTER_OFFSET_Y,
                        CONFIRM_BUTTON_SIZE_X, CONFIRM_BUTTON_SIZE_Y)
                .build();

        this.addRenderableWidget(input);
        this.addRenderableWidget(confirm);
    }

    @Override
    public void extractRenderState(@NonNull GuiGraphicsExtractor graphics, int i, int j, float f) {
        super.extractRenderState(graphics, i, j, f);

        graphics.text(minecraft.font,
                labelContent,
                width / 2 + LABEL_PHRASE_INPUT_CENTER_OFFSET_X,
                height / 2 + LABEL_PHRASE_INPUT_CENTER_OFFSET_Y,
                CommonColors.WHITE);
    }
}
