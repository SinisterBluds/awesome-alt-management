package me.axieum.mcmod.authme.api.util;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Minimal GitHub-release update check, modelled on the one used by the Fapcraft 1.12.2 project.
 * Queries the newest release tag and compares it to the locally installed mod version. Network
 * failures are silent (offline play), and the comparison is numeric so {@code v1.2.3},
 * {@code 1.2.3-ALPHA} and {@code 1.2.3+26.2} all parse.
 */
public final class UpdateChecker
{
    /** The repository whose releases are checked. */
    public static final String REPO = "SinisterBluds/awesome-alt-management";
    /** The GitHub latest-release API endpoint. */
    public static final String RELEASES_URL = "https://api.github.com/repos/" + REPO + "/releases/latest";

    private UpdateChecker() {}

    /** @return the newest release tag (e.g. {@code v3.2.1}) or null on any failure/offline. */
    public static String fetchLatestTag()
    {
        final JsonObject release = fetchLatestRelease();
        if (release == null) return null;
        if (release.has("tag_name")) return release.get("tag_name").getAsString();
        if (release.has("name")) return release.get("name").getAsString();
        return null;
    }

    private static JsonObject fetchLatestRelease()
    {
        try {
            final HttpURLConnection conn = (HttpURLConnection) new URL(RELEASES_URL).openConnection();
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(12000);
            conn.setInstanceFollowRedirects(true);
            conn.setRequestProperty("Accept", "application/vnd.github+json");
            conn.setRequestProperty("User-Agent", "awesome-alt-management (update checker)");
            if (conn.getResponseCode() != 200) return null;
            try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                final StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) sb.append(line);
                return new Gson().fromJson(sb.toString(), JsonObject.class);
            }
        } catch (Throwable ignored) {
            return null;
        }
    }

    /** [major, minor, patch] parsed from common tag formats (v1.2.3, 1.2.3-ALPHA, 1.2.3+26.2). */
    public static int[] parseVersion(String version)
    {
        if (version == null) return new int[] { 0, 0, 0 };
        String s = version.trim().replaceFirst("^[vV]", "").toLowerCase(Locale.ROOT);
        final int dash = s.indexOf('-');
        if (dash >= 0) s = s.substring(0, dash);
        final int plus = s.indexOf('+');
        if (plus >= 0) s = s.substring(0, plus);

        final StringBuilder digits = new StringBuilder();
        final List<Integer> numbers = new ArrayList<>();
        for (int i = 0; i < s.length(); i++) {
            final char c = s.charAt(i);
            if (Character.isDigit(c)) {
                digits.append(c);
            } else if (digits.length() > 0) {
                numbers.add(Integer.parseInt(digits.toString()));
                digits.setLength(0);
            }
        }
        if (digits.length() > 0) numbers.add(Integer.parseInt(digits.toString()));
        while (numbers.size() < 3) numbers.add(0);
        return new int[] { numbers.get(0), numbers.get(1), numbers.get(2) };
    }

    public static int compare(int[] a, int[] b)
    {
        for (int i = 0; i < 3; i++) {
            if (a[i] != b[i]) return Integer.compare(a[i], b[i]);
        }
        return 0;
    }

    /** True when {@code latestTag} is newer than {@code localVersion}. */
    public static boolean isOutdated(String localVersion, String latestTag)
    {
        if (localVersion == null || latestTag == null) return false;
        return compare(parseVersion(localVersion), parseVersion(latestTag)) < 0;
    }
}
