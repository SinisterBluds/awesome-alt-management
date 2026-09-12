package me.axieum.mcmod.authme.mixin;

import java.io.File;

import com.llamalad7.mixinextras.injector.wrapoperation.Operation;
import com.llamalad7.mixinextras.injector.wrapoperation.WrapOperation;
import me.axieum.mcmod.authme.config.Config;
import me.axieum.mcmod.authme.config.SecretsStorage;
import net.minecraft.client.main.GameConfig;
import org.slf4j.Logger;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;

import com.mojang.authlib.yggdrasil.YggdrasilAuthenticationService;

import net.minecraft.client.Minecraft;
import net.minecraft.server.Services;

import me.axieum.mcmod.authme.mixinHelper.YggdrasilAuthenticationServiceGetter;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Saves the YggdrasilAuthenticationService from initialization to be retrieved later.
 */
@Mixin(Minecraft.class)
public abstract class MinecraftMixin implements YggdrasilAuthenticationServiceGetter
{
    @Shadow
    @Final
    private static Logger LOGGER;

    /** Constructs a new Minecraft mixin instance. */
    public MinecraftMixin() {}

    @SuppressWarnings({"checkstyle:illegalidentifiername", "checkstyle:membername"})
    @Unique
    private YggdrasilAuthenticationService authme$authService;

    @SuppressWarnings({"checkstyle:linelength"})
    @WrapOperation(method = "<init>", at = @At(value = "INVOKE", target = "Lnet/minecraft/server/Services;create(Lcom/mojang/authlib/yggdrasil/YggdrasilAuthenticationService;Ljava/io/File;)Lnet/minecraft/server/Services;"))
    private Services wrapCreateServices(YggdrasilAuthenticationService yggdrasilAuthenticationService, File file, Operation<Services> original)
    {
        this.authme$authService = yggdrasilAuthenticationService;
        return original.call(yggdrasilAuthenticationService, file);
    }

    @SuppressWarnings({"checkstyle:illegalidentifiername"})
    @Override
    public YggdrasilAuthenticationService authme$getAuthService()
    {
        return this.authme$authService;
    }

    // to be honest, I think the Runtime#getRuntime#addShutdownHook suffices.
    // Also I don't think it is very good practice to use that in a Minecraft modification.
    /*@Inject(method = "destroy", at = @At("HEAD"))
    private void destroy(CallbackInfo ci) {
        if (!Config.LoginMethods.Microsoft.encryptRefreshTokens) SecretsStorage.save();
        else {
            if (!SecretsStorage.isPassPhraseSet()) return;

            if (!SecretsStorage.save()) {
                LOGGER.warn("Couldn't save secrets.");
            }
        }
    }*/
}
