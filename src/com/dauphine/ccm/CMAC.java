package com.dauphine.ccm;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * <p>
 * Implementation of a CMAC (Cipher-based Message Authentication Code) algorithm for AES.
 * This class provides methods for generating sub keys and authenticating messages using AES.
 * </p>
 *
 * <p>
 * It includes definitions for the irreducible polynomial, sub keys, and necessary cryptographic operations.
 * </p>
 *
 * <p>
 * This class is designed for use in cryptographic applications where message integrity and authenticity are crucial.
 * </p>
 *
 * @author Mathieu ANDRIN {@literal <mathieu.andrin@dauphine.eu>}
 * @author Ricardo BOKA {@literal <ricardo.boka@dauphine.eu>}
 * @see Cipher
 * @see SecretKey
 * @see SecretKeySpec
 */
public class CMAC {

    /**
     * Block size.
     */
    private static final int BLOCK_SIZE = 16;

    /**
     * Irreducible polynomial used for GF(2^128) multiplication.
     */
    private static final byte[] IRREDUCIBLE_POLYNOMIAL = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0x87
    };

    /**
     * Secret key for CMAC.
     *
     * @see SecretKey
     */
    private final SecretKey secretKey;

    /**
     * First sub key for CMAC.
     */
    private byte[] subKey1;

    /**
     * Second sub key for CMAC.
     */
    private byte[] subKey2;

    /**
     * Constructs a CMAC instance with the specified secret key.
     *
     * @param secretKey the secret key for CMAC.
     * @throws Exception if there is an error generating sub keys.
     * @see SecretKey
     */
    public CMAC(SecretKey secretKey) throws Exception {
        this.secretKey = secretKey;

        generateSubKeys();
    }

    /**
     * Computes the bitwise XOR of two byte arrays.
     *
     * @param array1 the first byte array.
     * @param array2 the second byte array.
     * @return the result of the XOR operation.
     */
    private static byte[] xor(byte[] array1, byte[] array2) {
        byte[] result = new byte[array1.length];

        for (int i = 0; i < array1.length; ++i) {
            result[i] = (byte) (array1[i] ^ array2[i]);
        }

        return result;
    }

    /**
     * Shifts the input byte array to the left by one bit.
     *
     * @param input the byte array to be shifted.
     * @return the result of the left shift operation.
     */
    private static byte[] shiftLeft(byte[] input) {
        byte[] shiftedArray = new byte[input.length];
        int carry = 0;

        for (int i = input.length - 1; i >= 0; --i) {
            shiftedArray[i] = (byte) ((input[i] << 1) | carry);
            carry = (input[i] & 0x80) != 0 ? 1 : 0;
        }

        return shiftedArray;
    }

    /**
     * Multiplies the input byte array in GF(2^128) with the irreducible polynomial.
     *
     * @param array the byte array to be multiplied.
     * @return the result of the multiplication.
     */
    private static byte[] gfMultiply(byte[] array) {
        byte[] result = shiftLeft(array);

        if ((array[0] & 0x80) != 0) {
            result = xor(result, IRREDUCIBLE_POLYNOMIAL);
        }

        return result;
    }

    /**
     * Example usage demonstrating CMAC (Cipher-based Message Authentication Code) computation.
     *
     * @param args Command line arguments (not used).
     * @throws Exception If CMAC computation fails.
     * @see Cipher
     * @see SecretKey
     * @see SecretKeySpec
     */
    public static void main(String[] args) throws Exception {
        String keyHexadecimal = "2B7E151628AED2A6ABF7158809CF4F3C";
        byte[] keyBytes = Utils.hexadecimalStringToByteArray(keyHexadecimal);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        CMAC cmac = new CMAC(secretKey);

        System.out.println("=================== Secret key ===================");
        System.out.println("Key: " + Utils.byteArrayToHexadecimalString(keyBytes));
        System.out.println("Sub key 1: " + Utils.byteArrayToHexadecimalString(cmac.subKey1));
        System.out.println("Sub key 2: " + Utils.byteArrayToHexadecimalString(cmac.subKey2));
        System.out.println("==================================================\n");

        String[] samples = {
                "",
                "6BC1BEE22E409F96E93D7E117393172A",
                "6BC1BEE22E409F96E93D7E117393172AAE2D8A57",
                "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710" // Longer message
        };

        for (int i = 0; i < samples.length; ++i) {
            String sample = samples[i];

            byte[] messageBytes = Utils.hexadecimalStringToByteArray(sample);
            byte[] mac = cmac.authenticate(messageBytes);

            System.out.println("===================== Sample =====================");
            System.out.println("Message: " + Utils.byteArrayToHexadecimalString(messageBytes));
            System.out.println("Tag: " + Utils.byteArrayToHexadecimalString(mac));
            System.out.println("==================================================" + (i < samples.length - 1 ? "\n" : ""));
        }
    }

    /**
     * Generates the sub keys k1 and k2 for CMAC.
     *
     * @throws Exception if there is an error during encryption.
     * @see Cipher
     * @see SecretKey
     */
    private void generateSubKeys() throws Exception {
        byte[] zeroesBlock = new byte[BLOCK_SIZE];
        byte[] encryptedZeroes = encrypt(zeroesBlock);

        subKey1 = gfMultiply(encryptedZeroes);
        subKey2 = gfMultiply(subKey1);
    }

    /**
     * Authenticates the given message using CMAC.
     *
     * @param message the message to be authenticated.
     * @return the CMAC of the message.
     * @throws Exception if there is an error during encryption.
     * @see Cipher
     * @see SecretKey
     */
    public byte[] authenticate(byte[] message) throws Exception {
        int messageLength = message.length;
        int numberOfBlockNeeded = (messageLength + BLOCK_SIZE - 1) / BLOCK_SIZE;
        boolean isLastBlockComplete = (messageLength % BLOCK_SIZE == 0);

        byte[] currentBlock;
        byte[] previousBlock = new byte[BLOCK_SIZE];

        if (numberOfBlockNeeded == 0) {
            numberOfBlockNeeded = 1;
            isLastBlockComplete = false;
        }

        for (int i = 0; i < numberOfBlockNeeded - 1; ++i) {
            currentBlock = new byte[BLOCK_SIZE];
            System.arraycopy(message, i * BLOCK_SIZE, currentBlock, 0, BLOCK_SIZE);
            previousBlock = encrypt(xor(previousBlock, currentBlock));
        }

        byte[] lastBlock = new byte[BLOCK_SIZE];
        int lastBlockStartIndex = (numberOfBlockNeeded - 1) * BLOCK_SIZE;
        int lastBlockLength = messageLength % BLOCK_SIZE;

        if (isLastBlockComplete) {
            System.arraycopy(message, lastBlockStartIndex, lastBlock, 0, BLOCK_SIZE);
            lastBlock = xor(lastBlock, subKey1);
        } else {
            System.arraycopy(message, lastBlockStartIndex, lastBlock, 0, lastBlockLength);
            lastBlock[lastBlockLength] = (byte) 0x80;
            lastBlock = xor(lastBlock, subKey2);
        }

        previousBlock = encrypt(xor(previousBlock, lastBlock));

        return previousBlock;
    }

    /**
     * Encrypts the input byte array using AES with ECB mode and no padding.
     *
     * @param plainText the byte array to be encrypted.
     * @return the encrypted byte array.
     * @throws Exception if there is an error during encryption.
     * @see Cipher
     * @see SecretKey
     */
    private byte[] encrypt(byte[] plainText) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES/ECB/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);

        return aesCipher.doFinal(plainText);
    }

}
