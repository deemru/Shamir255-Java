# Shamir255

[![Maven Central](https://img.shields.io/maven-central/v/io.github.deemru/shamir255.svg)](https://search.maven.org/artifact/io.github.deemru/shamir255)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Shamir255](https://github.com/deemru/Shamir255-Java) implements [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) algorithm over [GF(256)](https://en.wikipedia.org/wiki/Finite_field_arithmetic).

- Pure Java implementation (no external dependencies)
- Share size equals secret size (efficient storage)
- Supports secrets of any length
- Up to 255 shares with threshold from 2 to 255

## Installation

### Maven

Add this dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>io.github.deemru</groupId>
    <artifactId>shamir255</artifactId>
    <version>X.Y.Z</version>
</dependency>
```

### Gradle

Add this dependency to your `build.gradle`:

```gradle
dependencies {
    implementation 'io.github.deemru:shamir255:X.Y.Z'
}
```

### Gradle (Kotlin DSL)

Add this dependency to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("io.github.deemru:shamir255:X.Y.Z")
}
```

## Usage

### Java Example

```java
import io.github.deemru.shamir255.Shamir255;
import java.util.Map;
import java.util.HashMap;

// Original secret
String sensitive = "Hello, world!";
int needed = 2;  // Minimum shares needed to recover
int total = 3;   // Total shares to create

// Split secret into shares
Map<Integer, byte[]> shares = Shamir255.share(
    sensitive.getBytes(),
    needed,
    total
);

// Recover secret from any 2 shares
Map<Integer, byte[]> combine = new HashMap<>();
combine.put(1, shares.get(1));
combine.put(2, shares.get(2));

byte[] recovered = Shamir255.recover(combine);
String result = new String(recovered);

assert sensitive.equals(result); // true
```

### Kotlin Example

```kotlin
import io.github.deemru.shamir255.Shamir255

// Original secret
val sensitive = "Hello, world!"
val needed = 2  // Minimum shares needed to recover
val total = 3   // Total shares to create

// Split secret into shares
val shares = Shamir255.share(
    sensitive.toByteArray(),
    needed,
    total
)

// Recover secret from any 2 shares
val combine = mapOf(
    1 to shares[1]!!,
    2 to shares[2]!!
)

val recovered = Shamir255.recover(combine)
val result = String(recovered)

assert(sensitive == result) // true
```

## How It Works

**Shamir's Secret Sharing** is a cryptographic algorithm that splits a secret into multiple shares. The secret can only be reconstructed when a minimum number of shares (threshold) are combined.

### Key Properties

- **Secret size**: Any length
- **Share size**: Same as secret size
- **Threshold**: Minimum 2, maximum 255 shares
- **Total shares**: Maximum 255

### Example Scenarios

#### 2-of-3 Scheme
Split a secret into 3 shares where any 2 shares can recover the secret:
```java
byte[] secret = "Hello, world!".getBytes();
Map<Integer, byte[]> shares = Shamir255.share(secret, 2, 3);
// Any 2 of the 3 shares can recover the secret
```

#### 3-of-5 Scheme
Split a secret into 5 shares where any 3 shares can recover the secret:
```java
byte[] secret = "Hello, world!".getBytes();
Map<Integer, byte[]> shares = Shamir255.share(secret, 3, 5);
// Any 3 of the 5 shares can recover the secret
```

## API Reference

### `share(byte[] secret, int needed, int total)`

Splits a secret into multiple shares.

**Parameters:**
- `secret` - The secret to share (must not be empty)
- `needed` - Minimum number of shares required to recover the secret (2..total)
- `total` - Total number of shares to generate (needed..255)

**Returns:**
- `Map<Integer, byte[]>` - Map of share indices (1-based) to share bytes, or `null` on failure

### `recover(Map<Integer, byte[]> shares)`

Recovers the original secret from a set of shares.

**Parameters:**
- `shares` - Map of share indices to share bytes (must have at least 2 shares with valid indices 1..255)

**Returns:**
- `byte[]` - The recovered secret, or `null` on failure

## Requirements

- Java 8 or higher
- No external dependencies

## Compatibility

This Java implementation is **compatible** with the [PHP version](https://github.com/deemru/Shamir255). Shares created in PHP can be recovered in Java and vice versa.

## Security Notes

- Shares are generated using `SecureRandom` for cryptographic security
- The implementation uses GF(256) with primitive polynomial 0x11D from [RFC 6330](https://www.rfc-editor.org/rfc/rfc6330)
- Each share reveals no information about the secret by itself
- The secret can only be recovered with the minimum threshold of shares

## Testing

Run tests with Maven:

```bash
mvn test
```

The test suite includes:
- Basic functionality tests
- Edge cases (single byte, zero bytes, maximum shares)
- Cross-compatibility tests with PHP implementation
- Random testing with various configurations

CI:
- All tests run in GitHub Actions on every push and on tag releases.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Dmitrii Pichulin** ([@deemru](https://github.com/deemru))

## Related Projects

- [Shamir255 (PHP)](https://github.com/deemru/Shamir255) - Original PHP implementation
- [RFC 6330](https://www.rfc-editor.org/rfc/rfc6330) - GF(256) specification
- [How to share a secret (Shamir, 1979)](https://dl.acm.org/doi/10.1145/359168.359176) - Original paper describing the scheme implemented here
- [Shamir's Secret Sharing (Wikipedia)](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) - Overview of the algorithm

## Links

- [GitHub Repository](https://github.com/deemru/Shamir255-Java)
- [Maven Central](https://search.maven.org/artifact/io.github.deemru/shamir255)
- [Issue Tracker](https://github.com/deemru/Shamir255-Java/issues)
