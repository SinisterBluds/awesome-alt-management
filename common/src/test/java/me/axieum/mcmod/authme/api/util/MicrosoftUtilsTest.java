package me.axieum.mcmod.authme.api.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * Guards the refresh-token plumbing that everything else depends on: pasted-token normalisation and
 * the shape of the known-client table. A broken entry here would silently fail every login.
 */
class MicrosoftUtilsTest
{
    @Test
    void normalizeTokenStripsQuotesWhitespaceAndPrefixes()
    {
        assertEquals("M.C123_ABC.0", MicrosoftUtils.normalizeToken("  M.C123_ABC.0  "));
        assertEquals("M.C123_ABC.0", MicrosoftUtils.normalizeToken("\"M.C123_ABC.0\""));
        assertEquals("M.C123_ABC.0", MicrosoftUtils.normalizeToken("'M.C123_ABC.0'"));
        assertEquals("M.C123_ABC.0", MicrosoftUtils.normalizeToken("user:M.C123_ABC.0"));
        assertEquals("M.C123_ABC.0", MicrosoftUtils.normalizeToken("Bearer M.C123_ABC.0"));
        assertEquals("M.C123_ABC.0", MicrosoftUtils.normalizeToken("MCToken M.C123_ABC.0"));
        assertEquals("M.C123_ABC.0", MicrosoftUtils.normalizeToken("M.C123_ABC.0\r\n"));
        assertEquals("", MicrosoftUtils.normalizeToken("   "));
        assertEquals("", MicrosoftUtils.normalizeToken(null));
        // A real-shaped token with special MSA characters must survive intact (no colon -> untouched)
        final String real = "M.C533_SN1.0.U.MsaArtifacts.-Cp*e!Ed$Q-abc";
        assertEquals(real, MicrosoftUtils.normalizeToken(real));
    }

    @Test
    void knownClientsTableIsWellFormed()
    {
        assertEquals(10, MicrosoftUtils.KNOWN_CLIENTS.size());

        final MicrosoftUtils.Client first = MicrosoftUtils.KNOWN_CLIENTS.get(0);
        assertEquals("00000000402b5328", first.clientId());
        assertEquals("t", first.tokenType());

        final Set<String> ids = new HashSet<>();
        int legacy = 0;
        for (final MicrosoftUtils.Client client : MicrosoftUtils.KNOWN_CLIENTS) {
            assertTrue(ids.add(client.clientId()), "duplicate client id: " + client.clientId());
            assertTrue("t".equals(client.tokenType()) || "d".equals(client.tokenType()),
                "unexpected token type: " + client.tokenType());
            if ("t".equals(client.tokenType())) legacy++;
        }
        assertEquals(1, legacy, "only the Mojang client uses the t= ticket prefix");
        assertTrue(ids.contains("4358653d-21f6-4697-96bb-7963ff974196"), "Lunar client id missing");
        assertTrue(ids.contains("c36a9fb6-4f2a-41ff-90bd-ae7cc92031eb"), "Prism client id missing");
    }
}
