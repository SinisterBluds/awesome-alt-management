package me.axieum.mcmod.authme.api.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Guards the version parsing behind the update notice.
 */
class UpdateCheckerTest
{
    @Test
    void parsesCommonTagFormats()
    {
        assertArrayEquals(new int[] { 1, 2, 3 }, UpdateChecker.parseVersion("v1.2.3"));
        assertArrayEquals(new int[] { 1, 2, 3 }, UpdateChecker.parseVersion("1.2.3"));
        assertArrayEquals(new int[] { 1, 2, 3 }, UpdateChecker.parseVersion("1.2.3-ALPHA"));
        assertArrayEquals(new int[] { 1, 2, 3 }, UpdateChecker.parseVersion("1.2.3+26.2"));
        assertArrayEquals(new int[] { 3, 2, 0 }, UpdateChecker.parseVersion("3.2.0-ALPHA+26.2"));
        assertArrayEquals(new int[] { 0, 0, 0 }, UpdateChecker.parseVersion(null));
    }

    @Test
    void comparesNumericallyNotLexically()
    {
        assertTrue(UpdateChecker.isOutdated("3.2.0", "v3.2.1"));
        assertTrue(UpdateChecker.isOutdated("1.9.0", "1.10.0"));
        assertFalse(UpdateChecker.isOutdated("3.2.1", "v3.2.1"));
        assertFalse(UpdateChecker.isOutdated("3.3.0", "v3.2.9"));
        assertFalse(UpdateChecker.isOutdated("3.2.0", null));
    }
}
