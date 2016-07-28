import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

class CleartextCipher implements BlockCipher64 {
    public long encrypt(long block) {
        return block;
    }
    public long decrypt(long block) {
        return block;
    }
}

public class CBCEncryption {
    public static final Charset utf8 = StandardCharsets.UTF_8;
    public static final Random rng = new SecureRandom();

    public static byte[] stringToBytes(String s) {
        return s.getBytes(utf8);
    }

    public static String bytesToString(byte[] b) {
        return new String(b, utf8);
    }

    public static long randomIV() {
        // code here
        return 0;
    }

    public static String longToHexString(long x) {
        return Long.toHexString(x);
    }

    public static long hexStringToLong(String hex) {
        return new BigInteger(hex, 16).longValue();
    }

    public static boolean containsMatch(String s, String r) {
        return s.matches(String.format("(?i).*%s.*", r));
    }

    public static void main(String[] args) throws InvalidKeyException, FileNotFoundException {
        if(containsMatch(args[0], "partial"))
            partialBlockSample();
        if(containsMatch(args[0], "even"))
            evenBlockSample();
        if(containsMatch(args[0], "file"))
            fileSample(args[1], args[2]);
        if(containsMatch(args[0], "encrypt"))
            encryptFileBlowfish(stringToBytes(args[1]), args[2], args[3]);
        if(containsMatch(args[0], "decrypt"))
            decryptFileBlowfish(stringToBytes(args[1]), args[2], args[3]);
    }

    public static void fileSample(String keystring, String plaintext_filename) throws InvalidKeyException, FileNotFoundException {
        byte[] key = stringToBytes(keystring);
        String ciphertext_filename = plaintext_filename + ".secret.txt";
        String decrypted_filename = ciphertext_filename + ".opened.txt";
        encryptFileBlowfish(key, plaintext_filename, ciphertext_filename);
        decryptFileBlowfish(key, ciphertext_filename, decrypted_filename);
    }

    public static void partialBlockSample() throws InvalidKeyException, FileNotFoundException {
        String s = "abcdefghIJKLMNOP12";
        byte[] plaintext = stringToBytes(s); // opposite is bytesToString
        System.out.println("plaintext = " + Arrays.toString(plaintext));

        long firstBlock = longAt(plaintext, 0);
        long secondBlock = longAt(plaintext, 8);
        System.out.println("firstBlock               = " +
            Arrays.toString(BlockCipher64.longToBytes(firstBlock))); // opposite is BlockCipher64.bytesToLong
        System.out.println("secondBlock              = " +
            Arrays.toString(BlockCipher64.longToBytes(secondBlock)));
        System.out.println("firstBlock ^ secondBlock = " +
            Arrays.toString(BlockCipher64.longToBytes(firstBlock ^ secondBlock)));

        long iv = 0; // this makes it easier for us to see what's going on
        BlockCipher64 cipher = new CleartextCipher(); // same here

        byte[] ciphertext = encrypt(plaintext, cipher, iv);
        System.out.println("ciphertext = " + Arrays.toString(ciphertext));

        byte[] decrypted = decrypt(ciphertext, cipher, iv);
        System.out.println("decrypted = " + Arrays.toString(decrypted));

        System.out.println("bytesToString(decrypted) = " + bytesToString(decrypted));
    }

    public static void evenBlockSample() throws InvalidKeyException, FileNotFoundException {
        String s = "abcdefghIJKLMNOP";
        byte[] plaintext = stringToBytes(s); // opposite is bytesToString
        System.out.println("plaintext = " + Arrays.toString(plaintext));

        long firstBlock = longAt(plaintext, 0);
        long secondBlock = longAt(plaintext, 8);
        System.out.println("firstBlock               = " +
            Arrays.toString(BlockCipher64.longToBytes(firstBlock))); // opposite is BlockCipher64.bytesToLong
        System.out.println("secondBlock              = " +
            Arrays.toString(BlockCipher64.longToBytes(secondBlock)));
        System.out.println("firstBlock ^ secondBlock = " +
            Arrays.toString(BlockCipher64.longToBytes(firstBlock ^ secondBlock)));

        long iv = 0; // this makes it easier for us to see what's going on
        BlockCipher64 cipher = new CleartextCipher(); // same here

        byte[] ciphertext = encrypt(plaintext, cipher, iv);
        System.out.println("ciphertext = " + Arrays.toString(ciphertext));

        byte[] decrypted = decrypt(ciphertext, cipher, iv);
        System.out.println("decrypted = " + Arrays.toString(decrypted));

        System.out.println("bytesToString(decrypted) = " + bytesToString(decrypted));
    }

    public static long longAt(byte[] b, int pos) {
        return BlockCipher64.bytesToLong(Arrays.copyOfRange(b, pos, pos + 8));
    }

    public static void storeLongAt(byte[] b, long x, int pos) {
        byte[] c = BlockCipher64.longToBytes(x);
        for(int i = 0; i < 8 && (pos + i) < b.length; ++i) {
            b[pos + i] = c[i];
        }
    }

    public static byte[] encrypt(String plaintext, BlockCipher64 cipher, long IV) {
        return encrypt(stringToBytes(plaintext), cipher, IV);
    }

    /*
    Try making a message of 18 characters, printing out the bytes (stringToBytes and Arrays.toString),
    and printing out the bytes of the encrypt result using CleartextCipher and an IV of zero.
    How did the blocks change? Which blocks changed? Does the result make sense
    given the picture of how ciphertext stealing and chaining is supposed to work?
    Can you calculate what the first block xor'ed with the second block is?
     */
    public static byte[] encrypt(byte[] plaintext, BlockCipher64 cipher, long IV) {
        if(plaintext.length <= 8)
            throw new IllegalArgumentException("plaintext must be longer than 8 bytes!");

        byte[] ciphertext = new byte[plaintext.length];
        int blocks = plaintext.length / 8;
        if(plaintext.length % 8 != 0) ++blocks;

        long prev = IV;
        for(int block = 0; block < blocks; ++block) {
            prev = cipher.encrypt(prev ^ longAt(plaintext, block * 8));
            storeLongAt(ciphertext, prev, block * 8);
        }

        // copy penultimate to last, then prev to penultimate (ciphertext stealing)
        int lastBlock = (blocks - 1) * 8;
        int secondLastBlock = (blocks - 2) * 8;
        storeLongAt(ciphertext, longAt(ciphertext, secondLastBlock), lastBlock);
        storeLongAt(ciphertext, prev, secondLastBlock);

        return ciphertext;
    }

    public static long maskForLastNBytes(int n) {
        long result = 0;
        for(int i = 0; i < n; ++i) {
            result <<= 8;
            result |= 0xffL; // notice the L
        }
        return result;
    }

    public static long maskForFirstNBytes(int n) {
        // code here
        return 0;
    }

    public static long firstNBytesOfXRestFromY(int n, long x, long y) {
        // code here
        return 0;
    }

    public static byte[] decrypt(byte[] ciphertext, BlockCipher64 cipher, long IV) {
        // code here
        // check for an illegal argument

        // create a byte[] for the plaintext

        // calculate how many blocks there are

        // handle the last two blocks (which are special because of ciphertext stealing)

        // loop over all other blocks, decrypting and xor'ing, and saving the results

        return stringToBytes("hello");
    }

    public static String gatherMessage(Scanner sc) {
        StringBuilder sb = new StringBuilder();
        String line = sc.nextLine();
        while(!line.startsWith(">>>")) {
            sb.append(line);
            sb.append('\n');
            line = sc.nextLine();
        }
        sb.deleteCharAt(sb.length() - 1);
        return sb.toString();
    }

    public static String gatherBase64(Scanner sc) {
        StringBuilder sb = new StringBuilder();
        String line = sc.nextLine();
        // code here
        while(rng.nextInt() > 0 /* this is wrong. what condition goes here instead? */) {
            sb.append(line);
            line = sc.nextLine();
        }
        return sb.toString();
    }

    public static String breakInto64CharLines(String message) {
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for(char c : message.toCharArray()) {
            if(count == 64) {
                // code here
                // what should happen to count here?
                sb.append('\n');
            }
            sb.append(c);
            ++count;
        }
        return sb.toString();
    }

    /*
    Try encrypting the sample file with some key (remember the helper stringToBytes).
    Call this method in main with the file names. Check out the result file.
     */
    public static void encryptFileBlowfish(byte[] key, String input_filename, String output_filename)
        throws InvalidKeyException, FileNotFoundException {
        try (Scanner sc = new Scanner(new File(input_filename));
             PrintWriter write = new PrintWriter(output_filename)) {

            while(sc.hasNextLine()) {
                String line = sc.nextLine();
                if(!line.startsWith("<<<"))
                    write.println(line);
                else {
                    long iv = randomIV();
                    String message = gatherMessage(sc);
                    byte[] ciphertext = encrypt(message, new Blowfish(key), iv);
                    String encoded = Base64.getEncoder().encodeToString(ciphertext);
                    write.printf("<<< Base64 encoding of 16 round Blowfish in CBC " +
                                 "mode with ciphertext stealing. IV:%s\n", longToHexString(iv));
                    write.println(breakInto64CharLines(encoded));
                    write.println(">>>");
                }
            }
        }
    }

    /*
    This method should reverse the effect of encryptFileBlowfish. The result should reproduce
    the original file before encryption.
     */
    public static void decryptFileBlowfish(byte[] key, String input_filename, String output_filename)
        throws InvalidKeyException, FileNotFoundException {
        // code here
        // start by copy pasting encryptFile

        // when you find a line starting with "<<<"
            // get the IV
            // gather the encoded text
            // decode and decrypt it
            // turn the bytes back into a string
            // write out the <<< line, the message, and the >>> line
    }
}
