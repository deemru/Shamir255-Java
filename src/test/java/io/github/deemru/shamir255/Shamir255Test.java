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

        assertEquals( 3, shares.size() );

        // Recover using shares 1 and 2
        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 1, shares.get( 1 ) );
        combine.put( 2, shares.get( 2 ) );

        byte[] recovered = Shamir255.recover( combine );
        assertEquals( sensitive, new String( recovered ) );
    }

    @Test
    @DisplayName( "Share empty secret" )
    void testShareEmpty()
    {
        byte[] secret = new byte[0];
        Map<Integer, byte[]> shares = Shamir255.share( secret, 2, 3 );

        assertEquals( 3, shares.size() );

        // Each share should be exactly 256 bytes
        for( byte[] share : shares.values() )
            assertEquals( 256, share.length );

        // Recover from any 2 shares
        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 1, shares.get( 1 ) );
        combine.put( 2, shares.get( 2 ) );

        byte[] recovered = Shamir255.recover( combine );
        assertArrayEquals( secret, recovered );
    }

    @Test
    @DisplayName( "Share maximum size secret (255 bytes)" )
    void testShareMax()
    {
        byte[] secret = new byte[255];
        Arrays.fill( secret, (byte) 0xFF );

        Map<Integer, byte[]> shares = Shamir255.share( secret, 2, 3 );

        assertEquals( 3, shares.size() );

        // Each share should be exactly 256 bytes
        for( byte[] share : shares.values() )
            assertEquals( 256, share.length );

        // Recover from any 2 shares
        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 2, shares.get( 2 ) );
        combine.put( 3, shares.get( 3 ) );

        byte[] recovered = Shamir255.recover( combine );
        assertArrayEquals( secret, recovered );
    }

    @Test
    @DisplayName( "Share over maximum size secret (256 bytes) should throw exception" )
    void testShareOverMax()
    {
        byte[] secret = new byte[256];
        Arrays.fill( secret, (byte) 0xFF );

        assertThrows( IllegalArgumentException.class, () ->
        {
            Shamir255.share( secret, 2, 3 );
        } );
    }

    @Test
    @DisplayName( "Invalid parameters: needed < 2" )
    void testInvalidNeededTooSmall()
    {
        byte[] secret = "test".getBytes();

        assertThrows( IllegalArgumentException.class, () ->
        {
            Shamir255.share( secret, 1, 3 );
        } );
    }

    @Test
    @DisplayName( "Invalid parameters: needed > total" )
    void testInvalidNeededGreaterThanTotal()
    {
        byte[] secret = "test".getBytes();

        assertThrows( IllegalArgumentException.class, () ->
        {
            Shamir255.share( secret, 5, 3 );
        } );
    }

    @Test
    @DisplayName( "Null secret should throw exception" )
    void testNullSecret()
    {
        assertThrows( IllegalArgumentException.class, () ->
        {
            Shamir255.share( null, 2, 3 );
        } );
    }

    @Test
    @DisplayName( "Null shares should throw exception" )
    void testNullShares()
    {
        assertThrows( IllegalArgumentException.class, () ->
        {
            Shamir255.recover( null );
        } );
    }

    @Test
    @DisplayName( "Empty shares should throw exception" )
    void testEmptyShares()
    {
        assertThrows( IllegalArgumentException.class, () ->
        {
            Shamir255.recover( new HashMap<>() );
        } );
    }

    @Test
    @DisplayName( "Predefined shares from PHP version" )
    void testPredefined()
    {
        String sensitive = "Hello, world!";

        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 3, hexToBytes( "90f675126eac8d19c2ac2758e4edf396adac7397a882237bcb65431ab5218baface402d02e6c0f73cc5aa5c21700068a4cbdea78437bde260c86ec992e8a696190ad06db06f26d66768620115786ba32df8b4abbe4d9a1baea83c77167c73089582ac3edc5bb982057d18a5964281786762e44300425353d3617604cc70a2d119c6560728bd9f19f4be9f2c3ba06019431bf582040230ec549953b32b77cf6772c11ddc7cd0ab4bb9014672dfaa965344bc51855953afe05e16176aa41f76beb61b527248b37d88cc4be4871ede80bc2fc230ba83c0595e4105c77261aef3dc3e7952fa13687ddc26c3894626ac7ccaafbdc0faa96fdd39fa80fdf8dcb8d6eda" ) );
        combine.put( 7, hexToBytes( "0a19f38a88a5e88da14d980c30e3649cb24ad0f752888c8d0c92c7036c9cb213efdf84c29840b4e30f57512ef3d581936014716e3efb4a913a50f77b8b53e36c9ec28827e83c3571c5a1589cb54ea69a8e3b65d7681e4e67b0e77e829c28f2c0de842459a4fa7a59192dbf0c4f82fec280c56af2cd57e4a6e317911111728ddb7c98b6cc4c334868e1a29314e2bdf58488c4e9c1fc63eeb51de50743f4aa564102399cf2809bac1abc0a5e96b9a508ff8cc56ad5e5c62b053f146bed27524539a397a2d1ecb241880e73f60e1bfa9e013799e5da4fa702dcde9d7bea6cac91fa4cce345ec3ce09026dd829a1cb599d361258c697f1bc360cf75fd0bf8e6f4176" ) );
        combine.put( 9, hexToBytes( "5e9bcaa661864845afb7d1cb76370e087d5e0d18ec88d6331605cfc3bb6038b5cd9d55b3da5ed26647f5090b7ad72c8145b4f3db6c7fb3d98270aae192bed435347502817b8a7c6d076237e4a63996536c78c559c1c633f31565c5109619946cb923c030a19dd081cfd3ca25a371c7eb761c5ce9ddad883ee71d3a6e78ad5f258fd1101c0622a554f03d2f1f3f8f68b30a2c048102b4ea4ea2941474d780dc57e56c7e9e32da8d4e1a95a1b7312a02b6565a25019daefc33cf159c2c7921062df637877e25700992caa63b2a836b6b26ae7a5e4dbec7cc716e2037a4c193c4fd1f21a865fd10e37925e0c1d2cdb1268c78f682ecda7186f355a13e5c6be4ec9c" ) );

        byte[] recovered = Shamir255.recover( combine );
        assertEquals( sensitive, new String( recovered ) );
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
            {2, 2}, {2, 3}, {2, 5}, {3, 5}, {5, 10}, {7, 10}
        };

        for( String secret : secrets )
        {
            for( int[] combo : combinations )
            {
                int needed = combo[0];
                int total = combo[1];

                byte[] secretBytes = secret.getBytes();
                Map<Integer, byte[]> shares = Shamir255.share( secretBytes, needed, total );

                assertEquals( total, shares.size(), "Should have " + total + " shares" );

                // Verify each share is 256 bytes
                for( byte[] share : shares.values() )
                    assertEquals( 256, share.length, "Each share should be 256 bytes" );

                // Try recovering with exactly 'needed' shares
                Map<Integer, byte[]> combine = new HashMap<>();
                for( int i = 1; i <= needed; i++ )
                    combine.put( i, shares.get( i ) );

                byte[] recovered = Shamir255.recover( combine );
                assertArrayEquals( secretBytes, recovered,
                    "Failed to recover secret for needed=" + needed + ", total=" + total );
            }
        }
    }

    @Test
    @DisplayName( "Recover from different share combinations" )
    void testRecoverFromDifferentCombinations()
    {
        String sensitive = "Secret message";
        int needed = 3;
        int total = 5;

        Map<Integer, byte[]> shares = Shamir255.share( sensitive.getBytes(), needed, total );

        // Test different combinations of 3 shares from 5
        int[][] combinations =
        {
            {1, 2, 3},
            {1, 2, 4},
            {1, 2, 5},
            {1, 3, 4},
            {1, 3, 5},
            {1, 4, 5},
            {2, 3, 4},
            {2, 3, 5},
            {2, 4, 5},
            {3, 4, 5}
        };

        for( int[] combo : combinations )
        {
            Map<Integer, byte[]> combine = new HashMap<>();
            for( int shareNum : combo )
                combine.put( shareNum, shares.get( shareNum ) );

            byte[] recovered = Shamir255.recover( combine );
            assertArrayEquals( sensitive.getBytes(), recovered,
                "Failed to recover from shares: " + Arrays.toString( combo ) );
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

            assertEquals( total, shares.size() );

            for( byte[] share : shares.values() )
                assertEquals( 256, share.length );

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
            assertArrayEquals( secret, recovered );

            iterations++;
        }

        System.out.println( "Completed " + iterations + " iterations in 1 second" );
        assertTrue( iterations > 0, "Should complete at least one iteration" );
    }

    @Test
    @DisplayName( "Insufficient shares should fail" )
    void testInsufficientShares()
    {
        String sensitive = "Secret";
        int needed = 3;
        int total = 5;

        Map<Integer, byte[]> shares = Shamir255.share( sensitive.getBytes(), needed, total );

        Map<Integer, byte[]> combine = new HashMap<>();
        combine.put( 1, shares.get( 1 ) );
        combine.put( 2, shares.get( 2 ) );

        try
        {
            byte[] recovered = Shamir255.recover( combine );
            assertFalse( Arrays.equals( sensitive.getBytes(), recovered ),
                "Should not recover correct secret with insufficient shares" );
        }
        catch( IllegalArgumentException e )
        {
            // Expected: recovery may fail with invalid shares
        }
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
