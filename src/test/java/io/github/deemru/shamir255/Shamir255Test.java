package io.github.deemru.shamir255;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import java.util.HashMap;
import java.util.Arrays;
import java.util.Random;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Test suite for Shamir255.
 */
class Shamir255Test
{
    @Test
    @DisplayName( "Basic example from documentation" )
    void testBasicExample()
    {
        String sensitive = "Hello, world!";
        int needed = 2;
        int total = 3;

        Map<Integer, byte[]> shares = Shamir255.share( sensitive.getBytes(), needed, total );

        assertNotNull( shares );
        assertEquals( 3, shares.size() );

        // Recover using shares 1 and 2
        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 1, shares.get( 1 ) );
        combine.put( 2, shares.get( 2 ) );

        byte[] recovered = Shamir255.recover( combine );
        assertNotNull( recovered );
        assertEquals( sensitive, new String( recovered ) );
    }

    @Test
    @DisplayName( "Empty secret should return null" )
    void testShareEmpty()
    {
        byte[] secret = new byte[0];
        Map<Integer, byte[]> shares = Shamir255.share( secret, 2, 3 );
        assertNull( shares );
    }

    @Test
    @DisplayName( "Single byte secret" )
    void testSingleByteSecret()
    {
        String secret = "X";
        Map<Integer, byte[]> shares = Shamir255.share( secret.getBytes(), 2, 3 );

        assertNotNull( shares );

        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 1, shares.get( 1 ) );
        combine.put( 3, shares.get( 3 ) );

        byte[] recovered = Shamir255.recover( combine );
        assertNotNull( recovered );
        assertEquals( secret, new String( recovered ) );
    }

    @Test
    @DisplayName( "Secret with 0x00 bytes" )
    void testSecretWithZeroBytes()
    {
        byte[] secret = new byte[] { 0x00, 0x00, (byte) 0xFF, 0x00, (byte) 0xAB };
        Map<Integer, byte[]> shares = Shamir255.share( secret, 2, 3 );

        assertNotNull( shares );

        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 2, shares.get( 2 ) );
        combine.put( 3, shares.get( 3 ) );

        byte[] recovered = Shamir255.recover( combine );
        assertNotNull( recovered );
        assertArrayEquals( secret, recovered );
    }

    @Test
    @DisplayName( "All 0x00 secret" )
    void testAllZeroSecret()
    {
        Random random = new Random();
        int len = 32 + random.nextInt( 97 ); // 32-128
        byte[] secret = new byte[len];
        Arrays.fill( secret, (byte) 0x00 );

        Map<Integer, byte[]> shares = Shamir255.share( secret, 2, 3 );

        assertNotNull( shares );

        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 1, shares.get( 1 ) );
        combine.put( 2, shares.get( 2 ) );

        byte[] recovered = Shamir255.recover( combine );
        assertNotNull( recovered );
        assertArrayEquals( secret, recovered );
    }

    @Test
    @DisplayName( "All 0xFF secret" )
    void testAllFFSecret()
    {
        Random random = new Random();
        int len = 32 + random.nextInt( 97 ); // 32-128
        byte[] secret = new byte[len];
        Arrays.fill( secret, (byte) 0xFF );

        Map<Integer, byte[]> shares = Shamir255.share( secret, 2, 3 );

        assertNotNull( shares );

        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 1, shares.get( 1 ) );
        combine.put( 2, shares.get( 2 ) );

        byte[] recovered = Shamir255.recover( combine );
        assertNotNull( recovered );
        assertArrayEquals( secret, recovered );
    }

    @Test
    @DisplayName( "Invalid parameters: needed < 2" )
    void testInvalidNeededTooSmall()
    {
        byte[] secret = "test".getBytes();
        assertNull( Shamir255.share( secret, 1, 3 ) );
    }

    @Test
    @DisplayName( "Invalid parameters: needed > total" )
    void testInvalidNeededGreaterThanTotal()
    {
        byte[] secret = "test".getBytes();
        assertNull( Shamir255.share( secret, 5, 3 ) );
    }

    @Test
    @DisplayName( "Invalid parameters: total > 255" )
    void testInvalidTotalOver255()
    {
        byte[] secret = "test".getBytes();
        assertNull( Shamir255.share( secret, 2, 256 ) );
    }

    @Test
    @DisplayName( "Recover with less than 2 shares should return null" )
    void testRecoverLessThan2()
    {
        Map<Integer, byte[]> shares = Shamir255.share( "test".getBytes(), 2, 3 );
        assertNotNull( shares );

        Map<Integer, byte[]> single = new HashMap<>();
        single.put( 1, shares.get( 1 ) );

        assertNull( Shamir255.recover( single ) );
    }

    @Test
    @DisplayName( "Recover with x = 0 should return null" )
    void testRecoverXZero()
    {
        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 0, "test".getBytes() );
        combine.put( 1, "test".getBytes() );

        assertNull( Shamir255.recover( combine ) );
    }

    @Test
    @DisplayName( "Recover with x > 255 should return null" )
    void testRecoverXOver255()
    {
        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 256, "test".getBytes() );
        combine.put( 1, "test".getBytes() );

        assertNull( Shamir255.recover( combine ) );
    }

    @Test
    @DisplayName( "Recover with different lengths should return null" )
    void testRecoverDifferentLengths()
    {
        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 1, "test".getBytes() );
        combine.put( 2, "longer".getBytes() );

        assertNull( Shamir255.recover( combine ) );
    }

    @Test
    @DisplayName( "Recover with null share value should return null" )
    void testRecoverNullValue()
    {
        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 1, "test".getBytes() );
        combine.put( 2, null );

        assertNull( Shamir255.recover( combine ) );
    }

    @Test
    @DisplayName( "Predefined shares from PHP version 2.0.0" )
    void testPredefined()
    {
        String sensitive = "Hello, world!";

        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 3, hexToBytes( "3285dc7e245cf938d15ca186d0" ) );
        combine.put( 7, hexToBytes( "bcc9468ab6817877f565c39cc7" ) );
        combine.put( 9, hexToBytes( "faae632ae7ef520264b4962108" ) );

        byte[] recovered = Shamir255.recover( combine );
        assertNotNull( recovered );
        assertEquals( sensitive, new String( recovered ) );
    }

    @Test
    @DisplayName( "Share length equals secret length" )
    void testShareLengthEquals()
    {
        String secret = "test123";
        Map<Integer, byte[]> shares = Shamir255.share( secret.getBytes(), 2, 3 );

        assertNotNull( shares );

        for( byte[] share : shares.values() )
            assertEquals( secret.length(), share.length );
    }

    @Test
    @DisplayName( "3 of 3" )
    void test3of3()
    {
        String secret = "secret";
        Map<Integer, byte[]> shares = Shamir255.share( secret.getBytes(), 3, 3 );

        assertNotNull( shares );

        byte[] recovered = Shamir255.recover( shares );
        assertNotNull( recovered );
        assertEquals( secret, new String( recovered ) );
    }

    @Test
    @DisplayName( "2 of 5" )
    void test2of5()
    {
        String secret = "minimal threshold";
        Map<Integer, byte[]> shares = Shamir255.share( secret.getBytes(), 2, 5 );

        assertNotNull( shares );

        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 3, shares.get( 3 ) );
        combine.put( 5, shares.get( 5 ) );

        byte[] recovered = Shamir255.recover( combine );
        assertNotNull( recovered );
        assertEquals( secret, new String( recovered ) );
    }

    @Test
    @DisplayName( "5 of 7" )
    void test5of7()
    {
        String secret = "higher threshold test";
        Map<Integer, byte[]> shares = Shamir255.share( secret.getBytes(), 5, 7 );

        assertNotNull( shares );

        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 1, shares.get( 1 ) );
        combine.put( 3, shares.get( 3 ) );
        combine.put( 4, shares.get( 4 ) );
        combine.put( 6, shares.get( 6 ) );
        combine.put( 7, shares.get( 7 ) );

        byte[] recovered = Shamir255.recover( combine );
        assertNotNull( recovered );
        assertEquals( secret, new String( recovered ) );
    }

    @Test
    @DisplayName( "2 but 3 of 5 - insufficient shares" )
    void testInsufficientShares()
    {
        String secret = "secret data";
        Map<Integer, byte[]> shares = Shamir255.share( secret.getBytes(), 3, 5 );

        assertNotNull( shares );

        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 1, shares.get( 1 ) );
        combine.put( 2, shares.get( 2 ) );

        byte[] wrong = Shamir255.recover( combine );
        assertNotNull( wrong );
        assertNotEquals( secret, new String( wrong ) );
    }

    @Test
    @DisplayName( "2 of 255 - maximum shares" )
    void test2of255()
    {
        String secret = "max shares test";
        Map<Integer, byte[]> shares = Shamir255.share( secret.getBytes(), 2, 255 );

        assertNotNull( shares );
        assertEquals( 255, shares.size() );

        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 1, shares.get( 1 ) );
        combine.put( 255, shares.get( 255 ) );

        byte[] recovered = Shamir255.recover( combine );
        assertNotNull( recovered );
        assertEquals( secret, new String( recovered ) );
    }

    @Test
    @DisplayName( "Large secret (4 KiB)" )
    void testLargeSecret()
    {
        byte[] secret = new byte[4096];
        new Random().nextBytes( secret );

        Map<Integer, byte[]> shares = Shamir255.share( secret, 3, 5 );

        assertNotNull( shares );

        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 1, shares.get( 1 ) );
        combine.put( 3, shares.get( 3 ) );
        combine.put( 5, shares.get( 5 ) );

        byte[] recovered = Shamir255.recover( combine );
        assertNotNull( recovered );
        assertArrayEquals( secret, recovered );
    }

    @Test
    @DisplayName( "All 3 of 5 combinations" )
    void testAll3of5Combinations()
    {
        String secret = "TEST";
        Map<Integer, byte[]> shares = Shamir255.share( secret.getBytes(), 3, 5 );

        assertNotNull( shares );

        int[][] combos =
        {
            { 1, 2, 3 }, { 1, 2, 4 }, { 1, 2, 5 }, { 1, 3, 4 }, { 1, 3, 5 },
            { 1, 4, 5 }, { 2, 3, 4 }, { 2, 3, 5 }, { 2, 4, 5 }, { 3, 4, 5 },
        };

        for( int[] c : combos )
        {
            Map<Integer, byte[]> combine = new HashMap<>();
            combine.put( c[0], shares.get( c[0] ) );
            combine.put( c[1], shares.get( c[1] ) );
            combine.put( c[2], shares.get( c[2] ) );

            byte[] recovered = Shamir255.recover( combine );
            assertNotNull( recovered );
            assertArrayEquals( secret.getBytes(), recovered,
                "Failed for combination: " + Arrays.toString( c ) );
        }
    }

    @Test
    @DisplayName( "Different combinations of needed and total" )
    void testDifferentCombinations()
    {
        String[] secrets =
        {
            "A",
            "Short secret",
            "This is a longer secret that we want to share securely"
        };

        int[][] combinations =
        {
            { 2, 2 }, { 2, 3 }, { 2, 5 }, { 3, 5 }, { 5, 10 }, { 7, 10 }
        };

        for( String secret : secrets )
        {
            for( int[] combo : combinations )
            {
                int needed = combo[0];
                int total = combo[1];

                byte[] secretBytes = secret.getBytes();
                Map<Integer, byte[]> shares = Shamir255.share( secretBytes, needed, total );

                assertNotNull( shares, "Share returned null for needed=" + needed + ", total=" + total );
                assertEquals( total, shares.size(), "Should have " + total + " shares" );

                // Verify each share has same length as secret
                for( byte[] share : shares.values() )
                    assertEquals( secretBytes.length, share.length, "Each share should have same length as secret" );

                // Try recovering with exactly 'needed' shares
                Map<Integer, byte[]> combine = new HashMap<>();
                for( int i = 1; i <= needed; i++ )
                    combine.put( i, shares.get( i ) );

                byte[] recovered = Shamir255.recover( combine );
                assertNotNull( recovered );
                assertArrayEquals( secretBytes, recovered,
                    "Failed to recover secret for needed=" + needed + ", total=" + total );
            }
        }
    }

    @Test
    @DisplayName( "Complex random testing (1 second)" )
    void testComplexRandom()
    {
        Random random = new Random();
        long startTime = System.currentTimeMillis();
        int iterations = 0;

        while( System.currentTimeMillis() - startTime < 1000 )
        {
            int length = 1 + random.nextInt( 255 );
            byte[] secret = new byte[length];
            random.nextBytes( secret );

            int needed = 2 + random.nextInt( 9 );
            int total = needed + random.nextInt( 11 );

            Map<Integer, byte[]> shares = Shamir255.share( secret, needed, total );

            assertNotNull( shares );
            assertEquals( total, shares.size() );

            for( byte[] share : shares.values() )
                assertEquals( length, share.length );

            List<Integer> numbers = new ArrayList<>();
            for( int j = 1; j <= total; j++ )
                numbers.add( j );
            Collections.shuffle( numbers, random );

            Map<Integer, byte[]> combine = new HashMap<>();
            for( int j = 0; j < needed; j++ )
            {
                int shareNum = numbers.get( j );
                combine.put( shareNum, shares.get( shareNum ) );
            }

            byte[] recovered = Shamir255.recover( combine );
            assertNotNull( recovered );
            assertArrayEquals( secret, recovered );

            iterations++;
        }

        System.out.println( "Completed " + iterations + " iterations in 1 second" );
        assertTrue( iterations > 0, "Should complete at least one iteration" );
    }

    private static byte[] hexToBytes( String hex )
    {
        String normalized = hex.length() % 2 != 0 ? "0" + hex : hex;
        byte[] result = new byte[normalized.length() / 2];
        for( int i = 0; i < result.length; i++ )
            result[i] = (byte)Integer.parseInt( normalized.substring( i * 2, i * 2 + 2 ), 16 );
        return result;
    }
}
