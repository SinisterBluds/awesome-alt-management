package me.axieum.mcmod.authme.api.util;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.random.RandomGenerator;
import java.util.stream.Collectors;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpServer;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import net.minecraft.client.User;
import net.minecraft.util.GsonHelper;
import net.minecraft.util.Util;

import me.axieum.mcmod.authme.config.Config;
import static me.axieum.mcmod.authme.api.AuthMe.LOGGER;

/**
 * Utility methods for authenticating via Microsoft.
 *
 * <p>For more information refer to:
 * <a href="https://wiki.vg/Microsoft_Authentication_Scheme">https://wiki.vg/Microsoft_Authentication_Scheme</a>
 */
public final class MicrosoftUtils
{
    public static final String NO_REFRESH_TOKEN = "NO_REFRESH_TOKEN";

    /**
     * A reusable Apache HTTP request config
     *
     * <p>NB: We use Apache's HTTP implementation as the native HTTP client does
     * not appear to free its resources after use!
     */
    public static final RequestConfig REQUEST_CONFIG = RequestConfig
        .custom()
        .setConnectionRequestTimeout(30_000)
        .setConnectTimeout(30_000)
        .setSocketTimeout(30_000)
        .build();

    /** A secure random for OAuth2 state generation. */
    private static final RandomGenerator SECURE_RANDOM = new SecureRandom();

    /** The default client id used in the configuration. */
    public static final String CLIENT_ID = "9910bfa8-9924-4169-8264-fbb75752ebba";
    /** The default authorization url used in the configuration. */
    public static final String AUTHORIZE_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
    /** The default token url used in the configuration. */
    public static final String TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
    /** The default Xbox authentication url used in the configuration. */
    public static final String XBOX_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate";
    /** The default Xbox XSTS url used in the configuration. */
    public static final String XBOX_XSTS_URL = "https://xsts.auth.xboxlive.com/xsts/authorize";
    /** The default Minecraft authentication url used in the configuration. */
    public static final String MC_AUTH_URL = "https://api.minecraftservices.com/authentication/login_with_xbox";
    /** The default Minecraft profile url used in the configuration. */
    public static final String MC_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile";

    /**
     * A known OAuth client that mints Minecraft refresh tokens. A refresh token is bound to the
     * client that minted it, so it can only be exchanged by reproducing that exact client.
     *
     * @param name      human-readable launcher name
     * @param clientId  OAuth client id
     * @param scope     OAuth scope used when the token was minted
     * @param tokenType RPS ticket prefix for the resulting MSA token: {@code t} (legacy Live) or {@code d} (Azure app)
     */
    public record Client(String name, String clientId, String scope, String tokenType) {}

    /**
     * The result of exchanging a refresh token: the MSA access token, the (possibly rotated)
     * refresh token, and the client that accepted it.
     *
     * @param accessToken  MSA access token
     * @param refreshToken rotated refresh token to persist
     * @param tokenType    RPS ticket prefix to use for the XBL step
     * @param clientId     OAuth client id that accepted the token
     * @param clientName   human-readable launcher name
     */
    public record RefreshResult(String accessToken, String refreshToken, String tokenType,
                                String clientId, String clientName) {}

    /**
     * OAuth clients observed to mint Minecraft refresh tokens, in auto-detect order (common first).
     * Mojang uses the legacy Live endpoint and the {@code t=} ticket prefix; every Azure app uses
     * the {@code d=} prefix. The token endpoint is not part of the identity - the client id and
     * scope are - and the configured token url accepts all of them.
     */
    public static final List<Client> KNOWN_CLIENTS = List.of(
        new Client("Mojang",     "00000000402b5328",                     "service::user.auth.xboxlive.com::MBI_SSL", "t"),
        new Client("Prism",      "c36a9fb6-4f2a-41ff-90bd-ae7cc92031eb", "XboxLive.signin offline_access",           "d"),
        new Client("Lunar",      "4358653d-21f6-4697-96bb-7963ff974196", "XboxLive.signin offline_access",           "d"),
        new Client("LabyMod",    "27843883-6e3b-42cb-9e51-4f55a700601e", "XboxLive.signin offline_access",           "d"),
        new Client("PolyMC",     "6b329578-bfec-42a3-b503-303ab3f2ac96", "XboxLive.signin offline_access",           "d"),
        new Client("Technic",    "8dfabc1d-38a9-42d8-bc08-677dbc60fe65", "XboxLive.signin offline_access",           "d"),
        new Client("IAS",        "54fd49e4-2103-4044-9603-2b028c814ec3", "XboxLive.signin offline_access",           "d"),
        new Client("Adjust",     "c4f0db78-5015-4a94-8b34-1a4da87b9ce4", "XboxLive.signin offline_access",           "d"),
        new Client("Rise",       "ba89e6e0-8490-4a26-8746-f389a0d3ccc7", "XboxLive.signin offline_access",           "d"),
        new Client("Essentials", "e39cc675-eb52-4475-b5f8-82aaae14eeba", "XboxLive.signin offline_access",           "d"),
        new Client("HMCL",       "6a3728d6-27a3-4180-99bb-479895b8f88e", "XboxLive.signin offline_access",           "d"),
        new Client("PCL",        "fe72edc2-3a6f-4280-90e8-e2beb64ce7e1", "XboxLive.signin offline_access",           "d"),
        new Client("LiquidBounce","0add8caf-2cc6-4546-b798-c3d171217dd9", "XboxLive.signin offline_access",           "d"),
        new Client("BakaXL",     "e847355e-7e50-4859-b062-0e12640b9d8d", "XboxLive.signin offline_access",           "d"),
        new Client("STYLES",     "2289e44b-73ce-4577-bbd0-bb7f3c1a27cb", "XboxLive.signin offline_access",           "d"),
        new Client("KSYZ",       "42a60a84-599d-44b2-a7c6-b00cdef1d6a2", "XboxLive.signin offline_access",           "d"),
        new Client("AND1558",    "fa861065-c46c-4ac9-a4da-59a7d40b8a72", "XboxLive.signin offline_access",           "d"),
        new Client("MalChecker", "000000004c12ae6f",                     "service::user.auth.xboxlive.com::MBI_SSL", "t")
    );

    private MicrosoftUtils() {}

    /**
     * Navigates to the Microsoft login, and listens for a successful login
     * callback.
     *
     * <p>NB: You must manually interrupt the executor thread if the
     * completable future is cancelled!
     *
     * @param browserMessage function that takes true if success, and returns
     *                       a message to be shown in the browser after
     *                       logging in
     * @param executor       executor to run the login task on
     * @return completable future for the Microsoft auth token
     * @see #acquireMSAuthCode(Consumer, Function, Executor)
     */
    public static CompletableFuture<String> acquireMSAuthCode(
        final Function<Boolean, @NotNull String> browserMessage, final Executor executor
    )
    {
        return acquireMSAuthCode(url -> Util.getPlatform().openUri(url), browserMessage, executor);
    }

    /**
     * Navigates to the Microsoft login with user interaction, and listens for
     * a successful login callback.
     *
     * <p>NB: You must manually interrupt the executor thread if the
     * completable future is cancelled!
     *
     * @param browserMessage function that takes true if success, and returns
     *                       a message to be shown in the browser after
     *                       logging in
     * @param executor       executor to run the login task on
     * @param prompt         optional Microsoft interaction prompt override
     * @return completable future for the Microsoft auth token
     * @see #acquireMSAuthCode(Consumer, Function, Executor)
     */
    public static CompletableFuture<String> acquireMSAuthCode(
        final Function<Boolean, @NotNull String> browserMessage,
        final Executor executor,
        final @Nullable MicrosoftPrompt prompt
    )
    {
        return acquireMSAuthCode(url -> Util.getPlatform().openUri(url), browserMessage, executor, prompt);
    }

    /**
     * Generates a Microsoft login link, triggers the given browser action, and
     * listens for a successful login callback.
     *
     * <p>NB: You must manually interrupt the executor thread if the
     * completable future is cancelled!
     *
     * @param browserAction  consumer that opens the generated login url
     * @param browserMessage function that takes true if success, and returns
     *                       a message to be shown in the browser after
     *                       logging in
     * @param executor       executor to run the login task on
     * @return completable future for the Microsoft auth token
     */
    public static CompletableFuture<String> acquireMSAuthCode(
        final Consumer<URI> browserAction,
        final Function<Boolean, @NotNull String> browserMessage,
        final Executor executor
    )
    {
        return acquireMSAuthCode(browserAction, browserMessage, executor, null);
    }

    /**
     * Generates a Microsoft login link with user interaction, triggers the
     * given browser action, and listens for a successful login callback.
     *
     * <p>NB: You must manually interrupt the executor thread if the
     * completable future is cancelled!
     *
     * @param browserAction  consumer that opens the generated login url
     * @param browserMessage function that takes true if success, and returns
     *                       a message to be shown in the browser after
     *                       logging in
     * @param executor       executor to run the login task on
     * @param prompt         optional Microsoft interaction prompt override
     * @return completable future for the Microsoft auth token
     */
    public static CompletableFuture<String> acquireMSAuthCode(
        final Consumer<URI> browserAction,
        final Function<Boolean, @NotNull String> browserMessage,
        final Executor executor,
        final @Nullable MicrosoftPrompt prompt
    )
    {
        return CompletableFuture.supplyAsync(() -> {
            LOGGER.info("Acquiring Microsoft auth code...");
            try {
                // Generate a random "state" to be included in the request that will in turn be returned with the token
                final String state = generateState();

                // Prepare a temporary HTTP server we can listen for the OAuth2 callback on
                final HttpServer server = HttpServer.create(
                    new InetSocketAddress(Config.LoginMethods.Microsoft.port), 0
                );
                final CountDownLatch latch = new CountDownLatch(1); // track when a request has been handled
                final AtomicReference<@Nullable String> authCode = new AtomicReference<>(null),
                    errorMsg = new AtomicReference<>(null);

                server.createContext("/callback", exchange -> {
                    // Parse the query parameters
                    final Map<String, String> query = URLEncodedUtils
                        .parse(exchange.getRequestURI(), StandardCharsets.UTF_8)
                        .stream()
                        .collect(Collectors.toMap(NameValuePair::getName, NameValuePair::getValue));

                    // Check the returned parameter values
                    if (!state.equals(query.get("state"))) {
                        // The "state" does not match what we sent
                        errorMsg.set(
                            String.format("State mismatch! Expected '%s' but got '%s'.", state, query.get("state"))
                        );
                    } else if (query.containsKey("code")) {
                        // Successfully matched the auth code
                        authCode.set(query.get("code"));
                    } else if (query.containsKey("error")) {
                        // Otherwise, try to find an error description
                        errorMsg.set(String.format("%s: %s", query.get("error"), query.get("error_description")));
                    }

                    // Send a response informing that the browser may now be closed
                    final byte[] message = browserMessage.apply(errorMsg.get() == null).getBytes();
                    exchange.sendResponseHeaders(200, message.length);
                    final OutputStream res = exchange.getResponseBody();
                    res.write(message);
                    res.close();

                    // Let the caller thread know that the request has been handled
                    latch.countDown();
                });

                // Build a Microsoft login url
                final URIBuilder uriBuilder = new URIBuilder(Config.LoginMethods.Microsoft.authorizeUrl)
                    .addParameter("client_id", Config.LoginMethods.Microsoft.clientId)
                    .addParameter("response_type", "code")
                    .addParameter(
                        "redirect_uri", String.format("http://localhost:%d/callback", server.getAddress().getPort())
                    )
                    .addParameter("scope", "XboxLive.signin offline_access")
                    .addParameter("state", state);
                if (prompt != null || Config.LoginMethods.Microsoft.prompt != MicrosoftPrompt.DEFAULT) {
                    uriBuilder.addParameter(
                        "prompt", (prompt != null ? prompt : Config.LoginMethods.Microsoft.prompt).toString()
                    );
                }
                final URI uri = uriBuilder.build();

                // Navigate to the Microsoft login in browser
                LOGGER.info("Launching Microsoft login in browser: {}", uri.toString());
                browserAction.accept(uri);

                try {
                    // Start the HTTP server
                    LOGGER.info("Begin listening on http://localhost:{}/callback for a successful Microsoft login...",
                        server.getAddress().getPort());
                    server.start();

                    // Wait for the server to stop and return the auth code, if any captured
                    latch.await();
                    return Optional.ofNullable(authCode.get())
                                   .filter(code -> !code.isBlank())
                                   // If present, log success and return
                                   .map(code -> {
                                       LOGGER.info("Acquired Microsoft auth code! ({})",
                                           StringUtils.abbreviateMiddle(code, "...", 32));
                                       return code;
                                   })
                                   // Otherwise, throw an exception with the error description if present
                                   .orElseThrow(() -> new Exception(
                                       Optional.ofNullable(errorMsg.get())
                                               .orElse("There was no auth code or error description present.")
                                   ));
                } finally {
                    // Always release the server!
                    server.stop(2);
                }
            } catch (InterruptedException e) {
                LOGGER.warn("Microsoft auth code acquisition was cancelled!");
                throw new CancellationException("Interrupted");
            } catch (Exception e) {
                LOGGER.error("Unable to acquire Microsoft auth code!", e);
                throw new CompletionException(e);
            }
        }, executor);
    }

    /**
     * Exchanges a Microsoft auth code for an access token and a refresh token (Access Token, Refresh Token).
     *
     * <p>NB: You must manually interrupt the executor thread if the
     * completable future is cancelled!
     *
     * @param grant Microsoft auth code or refresh token
     * @param executor executor to run the login task on
     * @param useRefreshToken true to use a refresh token false to use an authcode
     * @return completable future for the Microsoft access and refresh token
     */
    public static CompletableFuture<Map.Entry<@NotNull String, @Nullable String>> acquireMSAccessRefreshToken(final String grant, final boolean useRefreshToken, final Executor executor)
    {
        return CompletableFuture.supplyAsync(() -> {
            LOGGER.info("Exchanging Microsoft auth code for an access token...");
            try (CloseableHttpClient client = HttpClients.createMinimal()) {
                // Build a new HTTP request
                final HttpPost request = new HttpPost(URI.create(Config.LoginMethods.Microsoft.tokenUrl));
                request.setConfig(REQUEST_CONFIG);
                request.setHeader("Content-Type", "application/x-www-form-urlencoded");
                request.setEntity(new UrlEncodedFormEntity(
                    form(Config.LoginMethods.Microsoft.clientId,
                         !useRefreshToken ? "authorization_code" : "refresh_token",
                         !useRefreshToken ? "code" : "refresh_token",
                         grant,
                         // The redirect URI only matters for the auth-code grant; a refresh grant
                         // must not carry a mismatched one or Microsoft rejects it.
                         !useRefreshToken
                             ? String.format("http://localhost:%d/callback", Config.LoginMethods.Microsoft.port)
                             : null),
                    "UTF-8"
                ));

                // Send the request on the HTTP client
                LOGGER.info("[{}] {} (timeout={}s)",
                    request.getMethod(), request.getURI().toString(), request.getConfig().getConnectTimeout() / 1000);
                final org.apache.http.HttpResponse res = client.execute(request);

                // Attempt to parse the response body as JSON and extract the access token
                final JsonObject json = GsonHelper.parse(EntityUtils.toString(res.getEntity()));
                String accessTokenAcquired;
                String refreshTokenAcquired;
                accessTokenAcquired = Optional.ofNullable(json.get("access_token"))
                               .map(JsonElement::getAsString)
                               .filter(token -> !token.isBlank())
                               // If present, log success and return
                               .map(token -> {
                                   LOGGER.info("Acquired Microsoft access token! ({})",
                                       StringUtils.abbreviateMiddle(token, "...", 32));
                                   return token;
                               })
                               // Otherwise, throw an exception with the error description if present
                               .orElseThrow(() -> new Exception(
                                   json.has("error") ? String.format(
                                       "%s: %s",
                                       json.get("error").getAsString(),
                                       json.get("error_description").getAsString()
                                   ) : "There was no access token or error description present."
                               ));
                refreshTokenAcquired = Optional.ofNullable(json.get("refresh_token"))
                        .map(JsonElement::getAsString)
                        .filter(token -> !token.isBlank())
                        // If present, log success and return
                        .map(token -> {
                            LOGGER.info("Acquired Microsoft refresh token! ({})",
                                    StringUtils.abbreviateMiddle(token, "...", 32));
                            return token;
                        })
                        // Otherwise, throw an exception with the error description if present
                        .orElse(null);
                if (refreshTokenAcquired == null) {
                    LOGGER.warn("Refresh Token was unable to be retrieved.");
                }
                return Map.entry(accessTokenAcquired, refreshTokenAcquired == null ? NO_REFRESH_TOKEN : refreshTokenAcquired);
            } catch (InterruptedException e) {
                LOGGER.warn("Microsoft access token acquisition was cancelled!");
                throw new CancellationException("Interrupted");
            } catch (Exception e) {
                LOGGER.error("Unable to acquire Microsoft access token!", e);
                throw new CompletionException(e);
            }
        }, executor);
    }

    /**
     * Exchanges a Microsoft access token for an Xbox Live access token.
     *
     * <p>NB: You must manually interrupt the executor thread if the
     * completable future is cancelled!
     *
     * @param accessToken Microsoft access token
     * @param executor    executor to run the login task on
     * @return completable future for the Xbox Live access token
     */
    public static CompletableFuture<String> acquireXboxAccessToken(final String accessToken, final Executor executor)
    {
        return acquireXboxAccessToken(accessToken, "d=", executor);
    }

    /**
     * Exchanges a Microsoft access token for an Xbox Live access token.
     *
     * @param accessToken Microsoft access token
     * @param tokenPrefix RPS ticket prefix ({@code t=} for legacy Live tokens, {@code d=} for Azure app tokens)
     * @param executor    executor to run the login task on
     * @return completable future for the Xbox Live access token
     */
    public static CompletableFuture<String> acquireXboxAccessToken(
        final String accessToken, final String tokenPrefix, final Executor executor
    )
    {
        return CompletableFuture.supplyAsync(() -> {
            LOGGER.info("Exchanging Microsoft access token for an Xbox Live access token...");
            try (CloseableHttpClient client = HttpClients.createMinimal()) {
                // Build a new HTTP request
                final HttpPost request = new HttpPost(URI.create(Config.LoginMethods.Microsoft.xboxAuthUrl));
                request.setConfig(REQUEST_CONFIG);
                request.setHeader("Content-Type", "application/json");
                request.setEntity(new StringEntity(
                    String.format("""
                        {
                          "Properties": {
                            "AuthMethod": "RPS",
                            "SiteName": "user.auth.xboxlive.com",
                            "RpsTicket": "%s%s"
                          },
                          "RelyingParty": "http://auth.xboxlive.com",
                          "TokenType": "JWT"
                        }""", tokenPrefix, accessToken)
                ));

                // Send the request on the HTTP client
                LOGGER.info("[{}] {} (timeout={}s)",
                    request.getMethod(), request.getURI().toString(), request.getConfig().getConnectTimeout() / 1000);
                final org.apache.http.HttpResponse res = client.execute(request);

                // Attempt to parse the response body as JSON and extract the access token
                // NB: No response body is sent if the response is not ok
                final JsonObject json = res.getStatusLine().getStatusCode() == 200
                                        ? GsonHelper.parse(EntityUtils.toString(res.getEntity()))
                                        : new JsonObject();
                return Optional.ofNullable(json.get("Token"))
                               .map(JsonElement::getAsString)
                               .filter(token -> !token.isBlank())
                               // If present, log success and return
                               .map(token -> {
                                   LOGGER.info("Acquired Xbox Live access token! ({})",
                                       StringUtils.abbreviateMiddle(token, "...", 32));
                                   return token;
                               })
                               // Otherwise, throw an exception with the error description if present
                               .orElseThrow(() -> new Exception(
                                   json.has("XErr") ? String.format(
                                       "%s: %s", json.get("XErr").getAsString(), json.get("Message").getAsString()
                                   ) : "There was no access token or error description present."
                               ));
            } catch (InterruptedException e) {
                LOGGER.warn("Xbox Live access token acquisition was cancelled!");
                throw new CancellationException("Interrupted");
            } catch (Exception e) {
                LOGGER.error("Unable to acquire Xbox Live access token!", e);
                throw new CompletionException(e);
            }
        }, executor);
    }

    /**
     * Exchanges an Xbox Live access token for an Xbox Live XSTS (security
     * token service) token.
     *
     * <p>NB: You must manually interrupt the executor thread if the
     * completable future is cancelled!
     *
     * @param accessToken Xbox Live access token
     * @param executor    executor to run the login task on
     * @return completable future for a mapping of Xbox Live XSTS token ("Token") and user hash ("uhs")
     */
    public static CompletableFuture<Map<String, String>> acquireXboxXstsToken(
        final String accessToken, final Executor executor
    )
    {
        return CompletableFuture.supplyAsync(() -> {
            LOGGER.info("Exchanging Xbox Live token for an Xbox Live XSTS token...");
            try (CloseableHttpClient client = HttpClients.createMinimal()) {
                // Build a new HTTP request
                final HttpPost request = new HttpPost(URI.create(Config.LoginMethods.Microsoft.xboxXstsUrl));
                request.setConfig(REQUEST_CONFIG);
                request.setHeader("Content-Type", "application/json");
                request.setEntity(new StringEntity(
                    String.format("""
                        {
                          "Properties": {
                            "SandboxId": "RETAIL",
                            "UserTokens": ["%s"]
                          },
                          "RelyingParty": "rp://api.minecraftservices.com/",
                          "TokenType": "JWT"
                        }""", accessToken)
                ));

                // Send the request on the HTTP client
                LOGGER.info("[{}] {} (timeout={}s)",
                    request.getMethod(), request.getURI().toString(), request.getConfig().getConnectTimeout() / 1000);
                final org.apache.http.HttpResponse res = client.execute(request);

                // Attempt to parse the response body as JSON and extract the access token and user hash
                // NB: No response body is sent if the response is not ok
                final JsonObject json = res.getStatusLine().getStatusCode() == 200
                                        ? GsonHelper.parse(EntityUtils.toString(res.getEntity()))
                                        : new JsonObject();
                return Optional.ofNullable(json.get("Token"))
                               .map(JsonElement::getAsString)
                               .filter(token -> !token.isBlank())
                               // If present, extract the user hash, log success and return
                               .map(token -> {
                                   // Extract the user hash
                                   final String uhs = json.get("DisplayClaims").getAsJsonObject()
                                                          .get("xui").getAsJsonArray()
                                                          .get(0).getAsJsonObject()
                                                          .get("uhs").getAsString();
                                   // Return an immutable mapping of the token and user hash
                                   LOGGER.info("Acquired Xbox Live XSTS token! (token={}, uhs={})",
                                       StringUtils.abbreviateMiddle(token, "...", 32), uhs);
                                   return Map.of("Token", token, "uhs", uhs);
                               })
                               // Otherwise, throw an exception with the error description if present
                               .orElseThrow(() -> new Exception(
                                   json.has("XErr") ? String.format(
                                       "%s: %s", json.get("XErr").getAsString(), json.get("Message").getAsString()
                                   ) : "There was no access token or error description present."
                               ));
            } catch (InterruptedException e) {
                LOGGER.warn("Xbox Live XSTS token acquisition was cancelled!");
                throw new CancellationException("Interrupted");
            } catch (Exception e) {
                LOGGER.error("Unable to acquire Xbox Live XSTS token!", e);
                throw new CompletionException(e);
            }
        }, executor);
    }

    /**
     * Exchanges an Xbox Live XSTS token for a Minecraft access token.
     *
     * <p>NB: You must manually interrupt the executor thread if the
     * completable future is cancelled!
     *
     * @param xstsToken Xbox Live XSTS token
     * @param userHash  Xbox Live user hash
     * @param executor  executor to run the login task on
     * @return completable future for the Minecraft access token
     */
    public static CompletableFuture<String> acquireMCAccessToken(
        final String xstsToken, final String userHash, final Executor executor
    )
    {
        return CompletableFuture.supplyAsync(() -> {
            LOGGER.info("Exchanging Xbox Live XSTS token for a Minecraft access token...");
            try (CloseableHttpClient client = HttpClients.createMinimal()) {
                // Build a new HTTP request
                final HttpPost request = new HttpPost(URI.create(Config.LoginMethods.Microsoft.mcAuthUrl));
                request.setConfig(REQUEST_CONFIG);
                request.setHeader("Content-Type", "application/json");
                request.setEntity(new StringEntity(
                    String.format("{\"identityToken\": \"XBL3.0 x=%s;%s\"}", userHash, xstsToken)
                ));

                // Send the request on the HTTP client
                LOGGER.info("[{}] {} (timeout={}s)",
                    request.getMethod(), request.getURI().toString(), request.getConfig().getConnectTimeout() / 1000);
                final org.apache.http.HttpResponse res = client.execute(request);

                // Attempt to parse the response body as JSON and extract the access token
                final JsonObject json = GsonHelper.parse(EntityUtils.toString(res.getEntity()));
                return Optional.ofNullable(json.get("access_token"))
                               .map(JsonElement::getAsString)
                               .filter(token -> !token.isBlank())
                               // If present, log success and return
                               .map(token -> {
                                   LOGGER.info("Acquired Minecraft access token! ({})",
                                       StringUtils.abbreviateMiddle(token, "...", 32));
                                   return token;
                               })
                               // Otherwise, throw an exception with the error description if present
                               .orElseThrow(() -> new Exception(
                                   json.has("errorMessage") ? String.format(
                                       "%s: %s", json.get("error").getAsString(), json.get("errorMessage").getAsString()
                                   ) : "There was no access token or error description present."
                               ));
            } catch (InterruptedException e) {
                LOGGER.warn("Minecraft access token acquisition was cancelled!");
                throw new CancellationException("Interrupted");
            } catch (Exception e) {
                LOGGER.error("Unable to acquire Minecraft access token!", e);
                throw new CompletionException(e);
            }
        }, executor);
    }

    /**
     * Fetches the Minecraft profile for the given access token, and returns a
     * new Minecraft session.
     *
     * <p>NB: You must manually interrupt the executor thread if the
     * completable future is cancelled!
     *
     * @param mcToken  Minecraft access token
     * @param executor executor to run the login task on
     * @return completable future for the new Minecraft session
     * @see SessionUtils#setUser(User) to apply the new session
     */
    public static CompletableFuture<User> login(final String mcToken, final Executor executor)
    {
        return CompletableFuture.supplyAsync(() -> {
            LOGGER.info("Fetching Minecraft profile...");
            try (CloseableHttpClient client = HttpClients.createMinimal()) {
                // Build a new HTTP request
                final HttpGet request = new HttpGet(URI.create(Config.LoginMethods.Microsoft.mcProfileUrl));
                request.setConfig(REQUEST_CONFIG);
                request.setHeader("Authorization", "Bearer " + mcToken);

                // Send the request on the HTTP client
                LOGGER.info("[{}] {} (timeout={}s)",
                    request.getMethod(), request.getURI().toString(), request.getConfig().getConnectTimeout() / 1000);
                final org.apache.http.HttpResponse res = client.execute(request);

                // Attempt to parse the response body as JSON and extract the profile
                final JsonObject json = GsonHelper.parse(EntityUtils.toString(res.getEntity()));
                return Optional.ofNullable(json.get("id"))
                               .map(JsonElement::getAsString)
                               .filter(uuid -> !uuid.isBlank())
                               // Parse the UUID (without hyphens)
                               .map(uuid -> UUID.fromString(
                                   uuid.replaceFirst(
                                       "([0-9a-fA-F]{8})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]+)",
                                       "$1-$2-$3-$4-$5"
                                   )
                               ))
                               // If present, log success, build a new session and return
                               .map(uuid -> {
                                   LOGGER.info("Fetched Minecraft profile! (name={}, uuid={})",
                                       json.get("name").getAsString(), uuid);
                                   return new User(
                                       json.get("name").getAsString(),
                                       uuid,
                                       mcToken,
                                       Optional.empty(),
                                       Optional.empty()
                                   );
                               })
                               // Otherwise, throw an exception with the error description if present
                               .orElseThrow(() -> new Exception(
                                   json.has("error") ? String.format(
                                       "%s: %s", json.get("error").getAsString(), json.get("errorMessage").getAsString()
                                   ) : "There was no profile or error description present."
                               ));
            } catch (InterruptedException e) {
                LOGGER.warn("Minecraft profile fetching was cancelled!");
                throw new CancellationException("Interrupted");
            } catch (Exception e) {
                LOGGER.error("Unable to fetch Minecraft profile!", e);
                throw new CompletionException(e);
            }
        }, executor);
    }

    /**
     * Normalises pasted token input: trims whitespace and quotes, removes newlines, strips a
     * {@code Bearer } / {@code MCToken } prefix and a Localts-style {@code username:} prefix.
     *
     * @param raw raw pasted value
     * @return the bare refresh token
     */
    public static String normalizeToken(final @Nullable String raw)
    {
        String value = raw == null ? "" : raw.trim();
        // Repeatedly strip a matching pair of surrounding quotes
        while (value.length() >= 2
            && ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'")))) {
            value = value.substring(1, value.length() - 1).trim();
        }
        value = value.replace("\r", "").replace("\n", "").trim();
        for (final String prefix : List.of("MCToken ", "Bearer ")) {
            if (value.regionMatches(true, 0, prefix, 0, prefix.length())) {
                value = value.substring(prefix.length()).trim();
            }
        }
        // Localts export: "username:M.C...." -> "M.C...."
        final int colon = value.indexOf(':');
        if (colon > 0 && colon < value.length() - 1) {
            final String prefix = value.substring(0, colon);
            if (!prefix.contains(".") && prefix.length() <= 32) {
                value = value.substring(colon + 1).trim();
            }
        }
        return value.trim();
    }

    /**
     * Exchanges a refresh token for an MSA access token by trying each known client, since a
     * refresh token is bound to the client that minted it. When a client id is already known it
     * is tried first, otherwise {@link #KNOWN_CLIENTS} order is used.
     *
     * @param rawToken      pasted refresh token
     * @param knownClientId client id that minted the token, or null to detect
     * @param executor      executor to run the network task on
     * @return completable future for the exchange result
     */
    public static CompletableFuture<RefreshResult> refreshMsaTokenAuto(
        final String rawToken, final @Nullable String knownClientId, final Executor executor
    )
    {
        return CompletableFuture.supplyAsync(() -> {
            final String refreshToken = normalizeToken(rawToken);
            if (refreshToken.isBlank()) {
                throw new CompletionException(new Exception("No refresh token was provided."));
            }

            // Build the try-order: the known client first (if any), then the rest.
            final List<Client> order = new ArrayList<>();
            if (knownClientId != null && !knownClientId.isBlank()) {
                for (final Client candidate : KNOWN_CLIENTS) {
                    if (candidate.clientId().equalsIgnoreCase(knownClientId.trim())) order.add(candidate);
                }
            }
            for (final Client candidate : KNOWN_CLIENTS) {
                if (!order.contains(candidate)) order.add(candidate);
            }

            String lastError = "unknown error";
            for (final Client candidate : order) {
                try {
                    final JsonObject json = postForm(
                        Config.LoginMethods.Microsoft.tokenUrl,
                        form(candidate.clientId(), "refresh_token", "refresh_token", refreshToken, null)
                    );
                    if (json.has("access_token")) {
                        final String rotated = json.has("refresh_token")
                                               ? json.get("refresh_token").getAsString()
                                               : refreshToken;
                        LOGGER.info("Refresh token accepted by {} ({})", candidate.name(), candidate.clientId());
                        return new RefreshResult(
                            json.get("access_token").getAsString(), rotated,
                            candidate.tokenType(), candidate.clientId(), candidate.name()
                        );
                    }
                    lastError = json.has("error") ? json.get("error").getAsString() : "no access_token in response";
                } catch (Exception e) {
                    lastError = e.getMessage();
                }
            }
            throw new CompletionException(new Exception(
                "No known launcher client accepted this refresh token (" + order.size() + " tried): "
                + lastError + ". It may be revoked, or minted by a client this build does not know."
            ));
        }, executor);
    }

    /**
     * Builds an OAuth form. {@code redirectUri} may be null (a refresh grant must not carry one).
     */
    private static List<BasicNameValuePair> form(
        final String clientId, final String grantType, final String grantKey, final String grantValue,
        final @Nullable String redirectUri
    )
    {
        final List<BasicNameValuePair> form = new ArrayList<>();
        form.add(new BasicNameValuePair("client_id", clientId));
        form.add(new BasicNameValuePair("grant_type", grantType));
        form.add(new BasicNameValuePair(grantKey, grantValue));
        if (redirectUri != null) form.add(new BasicNameValuePair("redirect_uri", redirectUri));
        return form;
    }

    /**
     * POSTs a form-urlencoded body to a url and parses the JSON response.
     */
    private static JsonObject postForm(final String url, final List<BasicNameValuePair> form) throws Exception
    {
        try (CloseableHttpClient client = HttpClients.createMinimal()) {
            final HttpPost request = new HttpPost(URI.create(url));
            request.setConfig(REQUEST_CONFIG);
            request.setHeader("Content-Type", "application/x-www-form-urlencoded");
            request.setHeader("Accept", "application/json");
            request.setEntity(new UrlEncodedFormEntity(form, "UTF-8"));
            final org.apache.http.HttpResponse res = client.execute(request);
            return GsonHelper.parse(EntityUtils.toString(res.getEntity()));
        }
    }

    /**
     * Generates a random OAuth2 state.
     *
     * @return OAuth2 state
     */
    public static String generateState()
    {
        byte[] randomBytes = new byte[16];
        SECURE_RANDOM.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Indicates the type of user interaction that is required when requesting
     * Microsoft authorization codes.
     */
    public enum MicrosoftPrompt
    {
        /**
         * Will use the default prompt, equivalent of not sending a prompt.
         */
        DEFAULT(""),

        /**
         * Will interrupt single sign-on providing account selection experience
         * listing all the accounts either in session or any remembered account
         * or an option to choose to use a different account altogether.
         */
        SELECT_ACCOUNT("select_account"),

        /**
         * Will force the user to enter their credentials on that request,
         * negating single-sign on.
         */
        LOGIN("login"),

        /**
         * Will ensure that the user isn't presented with any interactive
         * prompt whatsoever. If the request can't be completed silently via
         * single-sign on, the Microsoft identity platform will return an
         * {@code interaction_required} error.
         */
        NONE("none"),

        /**
         * Will trigger the OAuth consent dialog after the user signs in,
         * asking the user to grant permissions to the app.
         */
        CONSENT("consent");

        private final String prompt;

        /**
         * Constructs a new Microsoft Prompt enum.
         *
         * @param prompt prompt query value
         */
        MicrosoftPrompt(final String prompt)
        {
            this.prompt = prompt;
        }

        @Override
        public String toString()
        {
            return prompt;
        }
    }
}
