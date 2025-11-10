package io.github.deemru.shamir255;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 * Shamir's Secret Sharing implementation for secrets up to 255 bytes using 2048-bit MODP group.
 *
 * @see <a href="https://github.com/deemru/Shamir255-Java">Documentation</a>
 */
public class Shamir255
{
    // 2048-bit MODP Group @ https://www.ietf.org/rfc/rfc3526.html#section-3
    private static final BigInteger PRIME = new BigInteger(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    );

    private static final SecureRandom RANDOM = new SecureRandom();

    private static BigInteger generateCoefficient()
    {
        BigInteger coefficient;
        do
        {
            byte[] randomBytes = new byte[256];
            RANDOM.nextBytes( randomBytes );
            coefficient = new BigInteger( 1, randomBytes );
        }
        while( coefficient.compareTo( PRIME ) >= 0 );
        return coefficient;
    }

    private static BigInteger secretToBigInteger( byte[] secret )
    {
        byte[] prefixed = new byte[secret.length + 1];
        prefixed[0] = 'S';
        System.arraycopy( secret, 0, prefixed, 1, secret.length );
        return new BigInteger( 1, prefixed );
    }

    private static byte[] bigIntegerToSecret( BigInteger value )
    {
        byte[] bytes = value.toByteArray();

        int start = 0;
        if( bytes.length > 0 && bytes[0] == 0 )
            start = 1;

        if( bytes.length - start < 1 || bytes[start] != 'S' )
            return null;

        int secretStart = start + 1;
        int secretLength = bytes.length - secretStart;

        if( secretLength == 0 )
            return new byte[0];

        byte[] secret = new byte[secretLength];
        System.arraycopy( bytes, secretStart, secret, 0, secretLength );
        return secret;
    }

    private static byte[] padTo256Bytes( BigInteger value )
    {
        byte[] bytes = value.toByteArray();
        byte[] result = new byte[256];

        int start = 0;
        if( bytes.length > 0 && bytes[0] == 0 )
            start = 1;

        int length = bytes.length - start;
        System.arraycopy( bytes, start, result, 256 - length, length );
        return result;
    }

    /**
     * Splits a secret into multiple shares using Shamir's Secret Sharing scheme.
     *
     * @param secret the secret to share (up to 255 bytes)
     * @param needed minimum number of shares required to recover the secret (must be at least 2)
     * @param total  total number of shares to generate
     * @return a map of share indices (1-based) to share bytes
     * @throws IllegalArgumentException if parameters are invalid
     */
    public static Map<Integer, byte[]> share( byte[] secret, int needed, int total )
    {
        if( secret == null )
            throw new IllegalArgumentException( "Secret cannot be null" );

        if( secret.length > 255 )
            throw new IllegalArgumentException( "Secret must be up to 255 bytes" );

        if( needed < 2 )
            throw new IllegalArgumentException( "Needed must be at least 2" );

        if( needed > total )
            throw new IllegalArgumentException( "Needed cannot be greater than total" );

        BigInteger secretValue = secretToBigInteger( secret );

        BigInteger[] coefficients = new BigInteger[needed];
        coefficients[0] = secretValue;
        for( int i = 1; i < needed; i++ )
            coefficients[i] = generateCoefficient();

        Map<Integer, byte[]> shares = new HashMap<>();
        for( int x = 1; x <= total; x++ )
        {
            BigInteger y = BigInteger.ZERO;
            BigInteger xValue = BigInteger.valueOf( x );

            for( int i = 0; i < needed; i++ )
            {
                BigInteger term = coefficients[i].multiply( xValue.pow( i ) );
                y = y.add( term );
            }

            y = y.mod( PRIME );

            shares.put( x, padTo256Bytes( y ) );
        }

        return shares;
    }

    /**
     * Recovers the original secret from a set of shares using Lagrange interpolation.
     *
     * @param shares a map of share indices to share bytes (must have at least 'needed' shares)
     * @return the recovered secret
     * @throws IllegalArgumentException if shares is null or empty
     */
    public static byte[] recover( Map<Integer, byte[]> shares )
    {
        if( shares == null || shares.isEmpty() )
            throw new IllegalArgumentException( "Shares cannot be null or empty" );

        BigInteger secret = BigInteger.ZERO;

        for( Map.Entry<Integer, byte[]> entry1 : shares.entrySet() )
        {
            int xi = entry1.getKey();
            BigInteger yi = new BigInteger( 1, entry1.getValue() );

            BigInteger numerator = BigInteger.ONE;
            BigInteger denominator = BigInteger.ONE;

            for( Map.Entry<Integer, byte[]> entry2 : shares.entrySet() )
            {
                int xj = entry2.getKey();
                if( xi != xj )
                {
                    numerator = numerator.multiply( BigInteger.valueOf( -xj ) );
                    denominator = denominator.multiply( BigInteger.valueOf( xi - xj ) );
                }
            }

            BigInteger lagrangeCoefficient = numerator
                .multiply( denominator.modInverse( PRIME ) )
                .mod( PRIME );

            BigInteger term = yi.multiply( lagrangeCoefficient ).mod( PRIME );

            secret = secret.add( term ).mod( PRIME );
        }

        byte[] recovered = bigIntegerToSecret( secret );

        if( recovered == null )
            throw new IllegalArgumentException( "Failed to recover secret: invalid shares" );

        return recovered;
    }
}
