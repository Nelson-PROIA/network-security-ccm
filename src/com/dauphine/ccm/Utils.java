package com.dauphine.ccm;

/**
 * <p>
 * Utility class for handling byte array and hexadecimal string conversions.
 * </p>
 *
 * <p>
 * Provides methods to convert hexadecimal strings to byte arrays and vice versa,
 * and to format byte arrays as hexadecimal strings with optional block size.
 * </p>
 *
 * <p>
 * Designed for cryptographic applications requiring byte array manipulation and
 * hexadecimal representation.
 * </p>
 *
 * @author Nelson PROIA {@literal <nelson.proia@dauphine.eu>}
 */
public class Utils {

    /**
     * Block size in bytes.
     */
    private static final int BLOCK_SIZE = 16;

    /**
     * Converts a hexadecimal string to a byte array.
     *
     * @param hexadecimal the hexadecimal string to convert.
     * @return the resulting byte array.
     */
    public static byte[] hexadecimalStringToByteArray(String hexadecimal) {
        if (hexadecimal.length() % 2 == 1) {
            hexadecimal = "0" + hexadecimal;
        }

        int hexadecimalLength = hexadecimal.length();
        byte[] byteArray = new byte[hexadecimalLength / 2];

        for (int i = 0; i < hexadecimalLength; i += 2) {
            int firstDigit = Character.digit(hexadecimal.charAt(i), 16);
            int secondDigit = Character.digit(hexadecimal.charAt(i + 1), 16);
            byteArray[i / 2] = (byte) ((firstDigit << 4) + secondDigit);
        }

        return byteArray;
    }

    /**
     * Converts a byte array to a hexadecimal string with a default block size of 4 bytes.
     *
     * @param byteArray the byte array to convert.
     * @return the hexadecimal representation of the byte array.
     */
    public static String byteArrayToHexadecimalString(byte[] byteArray) {
        return byteArrayToHexadecimalString(byteArray, 4);
    }

    /**
     * Converts a byte array to a hexadecimal string with the specified block size.
     *
     * @param byteArray the byte array to convert.
     * @param blockSize the number of bytes per block in the output string.
     * @return the hexadecimal representation of the byte array.
     */
    public static String byteArrayToHexadecimalString(byte[] byteArray, int blockSize) {
        StringBuilder hexString = new StringBuilder();

        for (int i = 0; i < byteArray.length; ++i) {
            hexString.append(String.format("%02X", byteArray[i]));

            if ((i + 1) % blockSize == 0 && (i + 1) < byteArray.length) {
                hexString.append(" ");
            }
        }

        return hexString.toString();
    }

}
