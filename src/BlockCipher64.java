public interface BlockCipher64 {
    long encrypt(long block);
    long decrypt(long block);

    public static byte[] longToBytes(long l) {
        byte[] result = new byte[8];
        for (int i = 7; i >= 0; i--) {
            result[i] = (byte) l;
            l >>= 8;
        }
        return result;
    }

    public static long bytesToLong(byte[] b) {
        long result = 0;
        for (int i = 0; i < 8; i++) {
            result <<= 8;
            result |= ((long) b[i]) & 0xffL; // notice the L
        }
        return result;
    }
}
