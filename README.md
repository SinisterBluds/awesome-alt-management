# Awesome Alt Management

An in-game Minecraft account switcher for **Minecraft 26.2 (Fabric)** that logs in with a **Microsoft
(MSA) refresh token** and swaps the active session without restarting the game.

It is a fork of [multi-account-authme](https://github.com/BytelyPlay/multi-account-authme) by
axieum/BytelyPlay (MIT), extended with refresh-token login and per-token client auto-detection.

## Why this exists

A Microsoft refresh token is bound to the OAuth client that minted it. Prism, Lunar, LabyMod,
PolyMC, Technic and Mojang all mint tokens with different client ids, so a token from one launcher
cannot be refreshed by another. Most tools hardcode a single client id and silently fail on
everything else. This mod detects the minting client automatically.

## Features

- **Add account by token** — paste a refresh token (`M.C…`) in the GUI; the minting client is
  auto-detected. Also available as a command: `/alt <refresh token>`.
- **Client auto-detection** across ten known clients, with the correct RPS ticket prefix (`t=` for
  legacy Mojang tokens, `d=` for Azure-app tokens).
- **In-game session swap** — applies the new account live (profile, user API service, friends,
  social manager, profile keys, reporting context, Realms), no restart.
- **Saved accounts** — accounts are listed in the user-selection screen and re-logged in from their
  stored refresh token; tokens are encrypted at rest behind a pass phrase.
- The upstream browser and offline login flows are unchanged.

## Known client ids

| Launcher / app | Client id | Ticket prefix |
|----------------|-----------|---------------|
| Mojang (vanilla) | `00000000402b5328` | `t=` |
| Prism | `c36a9fb6-4f2a-41ff-90bd-ae7cc92031eb` | `d=` |
| Lunar (mid-2026+) | `4358653d-21f6-4697-96bb-7963ff974196` | `d=` |
| LabyMod | `27843883-6e3b-42cb-9e51-4f55a700601e` | `d=` |
| PolyMC | `6b329578-bfec-42a3-b503-303ab3f2ac96` | `d=` |
| Technic | `8dfabc1d-38a9-42d8-bc08-677dbc60fe65` | `d=` |
| IAS | `54fd49e4-2103-4044-9603-2b028c814ec3` | `d=` |
| Adjust | `c4f0db78-5015-4a94-8b34-1a4da87b9ce4` | `d=` |
| Rise | `ba89e6e0-8490-4a26-8746-f389a0d3ccc7` | `d=` |
| Essentials | `e39cc675-eb52-4475-b5f8-82aaae14eeba` | `d=` |

When a token is added, the client that accepts it is stored with the account so re-login is direct.

## Build

Requires JDK 25.

```bash
JAVA_HOME=$HOME/.sdkman/candidates/java/25.0.3.fx-zulu ./gradlew :fabric:build
```

Output: `fabric/build/libs/awesome-alt-management-fabric-<version>.jar`.

## Install

1. Minecraft **26.2** with **Fabric Loader** and **Fabric API**.
2. Drop `awesome-alt-management-fabric-<version>.jar` into the instance `mods/` folder.
3. Resourceful Config is bundled (jar-in-jar); no separate download needed.

## Usage

- Open the account screens from the auth button on the multiplayer screen (draggable), then choose
  **Add account by token** and paste a refresh token.
- Or run `/alt <refresh token>` in chat.
- Switch between saved accounts from the user-selection screen.

A pass phrase is requested on first use when token encryption is enabled (default). It is required to
save/load the account list.

## Verification

- Builds clean against the real Minecraft **26.2** client (Architectury Loom, JDK 25).
- Every mixin accessor/shadow target was checked against the 26.2 client jar, since a wrong target
  crashes at load and is invisible to the compiler: `Minecraft` fields (`user`, `userApiService`,
  `playerSocialManager`, `remoteFriendListUpdateHandler`, `profileKeyPairManager`, `reportingContext`,
  `profileFuture`, `realmsDataFetcher`), `RealmsClient.realmsClientInstance` plus its private
  `(String, String, Minecraft)` constructor, `RealmsAvailability.future`, `SplashManager.user`,
  `JoinMultiplayerScreen.lastScreen`, `RealmsGenericErrorScreen.nextScreen/detail`, and
  `DisconnectedScreen.parent/details` all exist in 26.2 as targeted.
- The refresh request shape matches the 26.1-26.2 reference mod Keychain (no `redirect_uri` on the
  refresh grant; same consumers endpoint and scope).
- The in-game session swap is a superset of what Keychain (sets only `mc.user`) and
  Change-My-Account (user, user API service, user properties) apply.
- `./gradlew :common:test` covers pasted-token normalisation and the known-client table invariants.
- The client id table was validated live against Microsoft's endpoints: all ten ids exist, and the
  Mojang, Prism, Lunar and LabyMod entries each refreshed a real account end to end.

## Notes

- A successful exchange returns a rotated refresh token; the mod persists it automatically.
- The Minecraft login endpoints rate-limit bursts (`429`); avoid adding many tokens back to back.
- Testing a token against the live service rotates it server-side — do not test tokens whose
  sessions must stay untouched.

## License

MIT, inherited from multi-account-authme (Copyright 2020-2026 Axieum and contributors). Original
project: <https://github.com/BytelyPlay/multi-account-authme>.
