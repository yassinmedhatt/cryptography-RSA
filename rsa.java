import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.IOException;

public class rsa {
    private static BigInteger generate256BitPrime() {
        SecureRandom secureRandom = new SecureRandom();
        return BigInteger.probablePrime(256, secureRandom);
    }

    public static BigInteger createPublicKey(BigInteger phi) {
        SecureRandom rand = new SecureRandom();
        BigInteger e;
        do {
            e = new BigInteger(phi.bitLength() - 1, rand).add(BigInteger.TWO);
        } while (!e.gcd(phi).equals(BigInteger.ONE));
        return e;
    }

    public static BigInteger calculatePHI(BigInteger p, BigInteger q) {
        return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    public static BigInteger calculate_n(BigInteger p, BigInteger q) {
        return p.multiply(q);
    }

    public static BigInteger[] generateKeyPair() {
        BigInteger p = generate256BitPrime();
        BigInteger q = generate256BitPrime();
        BigInteger phi = calculatePHI(p, q);
        BigInteger e = createPublicKey(phi);
        return new BigInteger[]{p, q, e};
    }

    public static String readMessage() throws IOException {
        return new String(Files.readAllBytes(Paths.get("message.txt")), StandardCharsets.UTF_8).trim();
    }

    public static BigInteger stringToBigInteger(String message) {
        return new BigInteger(1, message.getBytes(StandardCharsets.UTF_8));
    }

    public static void encryptAndSave(BigInteger message, BigInteger e, BigInteger n) throws IOException {
        BigInteger ciphertext = message.modPow(e, n);
        byte[] bytes = ciphertext.toByteArray();
        if (bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        String output = "the ciphertext in BigInteger is: " + ciphertext + "\n"
                     + "the ciphertext in plaintext is: " + fromBigIntegerToString(ciphertext);
        Files.write(Path.of("encrypted.txt"), output.toString().getBytes());
        System.out.println("Encrypted data saved to encrypted.txt");
    }

    public static BigInteger find_d(BigInteger e, BigInteger phi) {
        return e.modInverse(phi);
    }

    public static void DecryptandSave(BigInteger ciphertext, BigInteger d, BigInteger n) throws IOException {
        BigInteger decrypted = ciphertext.modPow(d, n);
        byte[] bytes = decrypted.toByteArray();
        if (bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        String plaintext = new String(bytes, StandardCharsets.UTF_8);
        String output = "The ciphertext in BigInteger is: " + ciphertext + "\n"
                     + "Decrypted message: " + plaintext;
        Files.write(Path.of("decrypted.txt"), output.getBytes(StandardCharsets.UTF_8));
        System.out.println("Decrypted successfully!");
    }

    public static String fromBigIntegerToString(BigInteger bigInteger) {
        return new String(bigInteger.toByteArray(), StandardCharsets.ISO_8859_1);
    }

    public static void main(String[] args) {
        String message;
        try {
            message = readMessage();
            System.out.println("Message: " + message);
        } catch (IOException e) {
            System.err.println("Error reading the message file: " + e.getMessage());
            return;
        }

        BigInteger messageBigInt = stringToBigInteger(message);
        BigInteger[] keyPair = generateKeyPair();
        BigInteger p = keyPair[0];
        BigInteger q = keyPair[1];
        BigInteger e = keyPair[2];
        BigInteger n = calculate_n(p, q);
        BigInteger phi = calculatePHI(p, q);
        BigInteger d = find_d(e, phi);

        try {
            encryptAndSave(messageBigInt, e, n);
            System.out.println("Generated public key in plaintext: " + fromBigIntegerToString(e));
            System.out.println("Generated public key in BigInteger: " + e);
        } catch (IOException ex) {
            System.err.println("Error during encryption: " + ex.getMessage());
        }

        BigInteger ciphertext = messageBigInt.modPow(e, n);
        try {
            DecryptandSave(ciphertext, d, n);
            System.out.println("Generated private key in plaintext: " + fromBigIntegerToString(d));
            System.out.println("Generated private key in BigInteger: " + d);
        } catch (IOException ex) {
            System.err.println("Error during decryption: " + ex.getMessage());
        }
    }
}