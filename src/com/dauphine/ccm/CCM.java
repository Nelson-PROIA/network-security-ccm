package com.dauphine.ccm;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

/**
 * <p>
 * Implementation of Counter with CBC-MAC (CCM) mode for AES encryption and decryption.
 * This class provides methods for encrypting and decrypting data with AES in CCM mode,
 * including tag generation and verification.
 * </p>
 *
 * <p>
 * CCM mode combines Counter (CTR) mode for encryption with CBC-MAC for tag generation.
 * It supports additional authenticated data (AAD) along with plaintext.
 * </p>
 *
 * <p>
 * This class is designed for cryptographic applications requiring authenticated encryption,
 * where both confidentiality and message integrity are critical.
 * </p>
 *
 * @author Sébastien GIRET-IMHAUS {@literal <sebastien.giret-imhaus@dauphine.eu>}
 * @author Nelson PROIA {@literal <nelson.proia@dauphine.eu>}
 * @see Cipher
 * @see SecretKey
 * @see SecretKeySpec
 * @see IvParameterSpec
 */
public class CCM {

    /**
     * Block size.
     */
    private static final int BLOCK_SIZE = 16;

    /**
     * The AES secret key used for encryption and decryption operations.
     */
    private final SecretKey secretKey;

    /**
     * Constructs a CCM instance with the provided AES secret key.
     *
     * @param secretKey The AES secret key to use for encryption and decryption.
     * @see SecretKey
     */
    public CCM(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public static byte[] hexStringToByteArray(String hexadecimal) {
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
     * Converts a byte array to a hexadecimal string.
     *
     * @param byteArray the byte array to convert.
     * @return the hexadecimal representation of the byte array.
     */
    public static String byteArrayToHexString(byte[] byteArray) {
        StringBuilder hexString = new StringBuilder();

        for (byte b : byteArray) {
            hexString.append(String.format("%02X", b));
        }

        return hexString.toString();
    }

    /**
     * Formats the input data for generating the tag.
     *
     * @param nonce          Nonce value for encryption.
     * @param associatedData Associated data.
     * @param plainText      Plaintext to be encrypted.
     * @param tagLength      Length of the tag to be generated.
     * @return Formatted input for tag generation.
     */
    private static byte[] formatedTagInput(byte[] nonce, byte[] associatedData, byte[] plainText, int tagLength) {
        byte[] formattedNonce = new byte[BLOCK_SIZE];
        formattedNonce[0] |= 0x40;

        int tagLengthAdjustment = (tagLength - 2) / 2;
        formattedNonce[0] |= (byte) (((tagLengthAdjustment % 2) + (((tagLengthAdjustment / 2) % 2) * 2) + (((tagLengthAdjustment / 4) % 2)) * 4) * 8);

        int nonceLengthAdjustment = 14 - nonce.length;
        formattedNonce[0] |= (byte) (nonceLengthAdjustment % 2 + ((nonceLengthAdjustment / 2) % 2) * 2 + (((nonceLengthAdjustment / 4) % 2) * 4));

        System.arraycopy(nonce, 0, formattedNonce, 1, nonce.length);

        String plaintextHexadecimalLength = Integer.toHexString(plainText.length);
        byte[] plaintextHexadecimalBytes = hexStringToByteArray(plaintextHexadecimalLength);

        for (int i = 0; i < plaintextHexadecimalBytes.length; ++i) {
            formattedNonce[BLOCK_SIZE + i - plaintextHexadecimalBytes.length] |= plaintextHexadecimalBytes[i];
        }

        byte[] formattedAssociatedData;

        if (associatedData.length > 0) {
            if (associatedData.length < 65280) {
                formattedAssociatedData = new byte[2 + associatedData.length + ((2 + associatedData.length) % BLOCK_SIZE == 0 ? 0 : BLOCK_SIZE - ((2 + associatedData.length) % BLOCK_SIZE))];
                formattedAssociatedData[0] = (byte) (associatedData.length / 256);
                formattedAssociatedData[1] = (byte) (associatedData.length % 256);
                System.arraycopy(associatedData, 0, formattedAssociatedData, 2, associatedData.length);
            } else {
                formattedAssociatedData = new byte[6 + associatedData.length + ((6 + associatedData.length) % BLOCK_SIZE == 0 ? 0 : BLOCK_SIZE - ((6 + associatedData.length) % BLOCK_SIZE))];
                formattedAssociatedData[0] = (byte) 0xff;
                formattedAssociatedData[1] = (byte) 0xfe;

                int length = associatedData.length;
                for (int i = 0; i < 6; ++i) {
                    formattedAssociatedData[7 - i] = (byte) (length % 256);
                    length /= 256;
                }

                System.arraycopy(associatedData, 0, formattedAssociatedData, 6, associatedData.length);
            }
        } else {
            formattedAssociatedData = new byte[0];
        }

        byte[] formattedPlaintext = new byte[plainText.length + (plainText.length % BLOCK_SIZE == 0 ? 0 : BLOCK_SIZE - (plainText.length % BLOCK_SIZE))];
        System.arraycopy(plainText, 0, formattedPlaintext, 0, plainText.length);

        byte[] input = new byte[formattedNonce.length + formattedAssociatedData.length + formattedPlaintext.length];
        System.arraycopy(formattedNonce, 0, input, 0, formattedNonce.length);
        System.arraycopy(formattedAssociatedData, 0, input, formattedNonce.length, formattedAssociatedData.length);
        System.arraycopy(formattedPlaintext, 0, input, formattedNonce.length + formattedAssociatedData.length, formattedPlaintext.length);

        if (associatedData.length == 0) {
            input[0] = 15;
        }

        return input;
    }

    /**
     * Formats the counter for encryption initialization vector (IV).
     *
     * @param nonce Nonce value for encryption.
     * @return Formatted IV for encryption.
     * @see IvParameterSpec
     */
    private static IvParameterSpec formatedCounter(byte[] nonce) {
        byte[] formattedIV = new byte[BLOCK_SIZE];
        int nonceLengthAdjustment = 14 - nonce.length;

        formattedIV[0] |= (byte) (nonceLengthAdjustment % 2 + ((nonceLengthAdjustment / 2) % 2) * 2 + (((nonceLengthAdjustment / 4) % 2) * 4));

        System.arraycopy(nonce, 0, formattedIV, 1, nonce.length);

        return new IvParameterSpec(formattedIV);
    }

    /**
     * The main method is the entry point for the application.
     *
     * @param args Command-line arguments (not used in this application).
     * @throws Exception If any exception occurs during execution.
     */
    public static void main(String[] args) throws Exception {
        System.out.println("CCM:\n");
        CCM.testCCM();

        System.out.println("\nCMAC:\n");
        CMAC.testCMAC();
    }

    /**
     * Example usage demonstrating CCM (Counter with CBC-MAC) mode computation.
     *
     * @throws Exception If encryption or decryption fails.
     * @see Cipher
     * @see SecretKey
     * @see SecretKeySpec
     */
    public static void testCCM() throws Exception {
        String keyHexadecimal = "404142434445464748494A4B4C4D4E4F";
        byte[] keyBytes = hexStringToByteArray(keyHexadecimal);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        CCM ccm = new CCM(secretKey);

        System.out.println("=================== Secret key ===================");
        System.out.println("Key: " + byteArrayToHexString(keyBytes));
        System.out.println("==================================================\n");

        String[][] samples = {
                {"10111213141516", "0001020304050607", "20212223", "4"},
                {"1011121314151617", "000102030405060708090A0B0C0D0E0F", "202122232425262728292A2B2C2D2E2F", "6"},
                {"101112131415161718191A1B", "000102030405060708090A0B0C0D0E0F10111213", "202122232425262728292A2B2C2D2E2F3031323334353637", "8"},
                {"10111213141516", "", "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F", "4"},
                {"10111213141516", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", "", "4"}
        };

        for (int i = 0; i < samples.length; ++i) {
            String[] sample = samples[i];

            String nonceHexadecimal = sample[0];
            String associatedDataHexadecimal = sample[1];
            String plainTextHexadecimal = sample[2];
            int tagLength = Integer.parseInt(sample[3]);

            byte[] nonce = hexStringToByteArray(nonceHexadecimal);
            byte[] associatedData = hexStringToByteArray(associatedDataHexadecimal);
            byte[] plainText = hexStringToByteArray(plainTextHexadecimal);

            byte[] cipher = ccm.encryptGenerate(nonce, associatedData, plainText, tagLength);
            byte[] decrypted = ccm.decryptVerify(nonce, associatedData, cipher, tagLength);

            System.out.println("===================== Sample =====================");
            System.out.println("Nonce: " + byteArrayToHexString(nonce));
            System.out.println("Associated data: " + byteArrayToHexString(associatedData));
            System.out.println("Plain text: " + byteArrayToHexString(plainText));
            System.out.println("Tag Length: " + (tagLength * 8) + " bits");
            System.out.println("\nEncrypted Hexadecimal: " + byteArrayToHexString(cipher));
            System.out.println("Decrypted Hexadecimal: " + byteArrayToHexString(decrypted));
            System.out.println("==================================================" + (i < samples.length - 1 ? "\n" : ""));
        }
    }

    /**
     * Generates the authentication tag for the given data.
     *
     * @param nonce          Nonce value for encryption.
     * @param associatedData Associated data.
     * @param plainText      Plaintext to be encrypted.
     * @param tagLength      Length of the tag to be generated.
     * @return Authentication tag for the encrypted data.
     * @throws Exception If encryption or tag generation fails.
     * @see Cipher
     * @see SecretKey
     */
    private byte[] tag(byte[] nonce, byte[] associatedData, byte[] plainText, int tagLength) throws Exception {
        byte[] formattedInput = formatedTagInput(nonce, associatedData, plainText, tagLength);

        Cipher aesCipher = Cipher.getInstance("AES/CBC/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[BLOCK_SIZE]));

        byte[] encryptedData = aesCipher.doFinal(formattedInput);

        byte[] authenticationTag = new byte[tagLength];
        System.arraycopy(encryptedData, encryptedData.length - BLOCK_SIZE, authenticationTag, 0, tagLength);

        return authenticationTag;
    }

    /**
     * Encrypts the plaintext along with generating and appending the authentication tag.
     *
     * @param nonce          Nonce value for encryption.
     * @param associatedData Associated data.
     * @param plainText      Plaintext to be encrypted.
     * @param tagLength      Length of the tag to be generated.
     * @return Encrypted data with appended authentication tag.
     * @throws Exception If encryption or tag generation fails.
     * @see Cipher
     * @see SecretKey
     */
    public byte[] encryptGenerate(byte[] nonce, byte[] associatedData, byte[] plainText, int tagLength) throws Exception {
        byte[] authenticationTag = tag(nonce, associatedData, plainText, tagLength);
        Cipher aesCipher = Cipher.getInstance("AES/CTR/NoPadding");

        IvParameterSpec counter = formatedCounter(nonce);
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, counter);
        byte[] encryptedTag = aesCipher.doFinal(authenticationTag);

        byte[] incrementedCounter = counter.getIV();
        ++incrementedCounter[incrementedCounter.length - 1];
        IvParameterSpec counterPlus1 = new IvParameterSpec(incrementedCounter);

        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, counterPlus1);
        byte[] encryptedPlainText = aesCipher.doFinal(plainText);

        byte[] encryptedData = new byte[encryptedPlainText.length + encryptedTag.length];
        System.arraycopy(encryptedPlainText, 0, encryptedData, 0, encryptedPlainText.length);
        System.arraycopy(encryptedTag, 0, encryptedData, encryptedPlainText.length, encryptedTag.length);

        return encryptedData;
    }

    /**
     * Decrypts the data and verifies the appended authentication tag.
     *
     * @param nonce          Nonce value for decryption.
     * @param associatedData Associated data used during encryption.
     * @param cipher         Encrypted data with appended authentication tag.
     * @param tagLength      Length of the tag appended to the cipher.
     * @return Decrypted plaintext if tag verification succeeds; otherwise, an empty byte array.
     * @throws Exception If decryption or tag verification fails.
     * @see Cipher
     * @see SecretKey
     */
    public byte[] decryptVerify(byte[] nonce, byte[] associatedData, byte[] cipher, int tagLength) throws Exception {
        byte[] encryptedText = Arrays.copyOfRange(cipher, 0, cipher.length - tagLength);
        byte[] encryptedTag = Arrays.copyOfRange(cipher, cipher.length - tagLength, cipher.length);

        Cipher aesCipher = Cipher.getInstance("AES/CTR/NoPadding");

        IvParameterSpec counter = formatedCounter(nonce);
        aesCipher.init(Cipher.DECRYPT_MODE, secretKey, counter);

        byte[] decryptedTag = aesCipher.doFinal(encryptedTag);

        byte[] incrementedCounter = counter.getIV();
        ++incrementedCounter[incrementedCounter.length - 1];
        IvParameterSpec counterPlus1 = new IvParameterSpec(incrementedCounter);

        aesCipher.init(Cipher.DECRYPT_MODE, secretKey, counterPlus1);
        byte[] decryptedText = aesCipher.doFinal(encryptedText);

        byte[] recalculatedTag = tag(nonce, associatedData, decryptedText, tagLength);

        if (Arrays.equals(decryptedTag, recalculatedTag)) {
            return decryptedText;
        }

        return new byte[0];
    }

}

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
class CMAC {

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
    private static byte[] gfMult(byte[] array) {
        byte[] result = shiftLeft(array);

        if ((array[0] & 0x80) != 0) {
            result = xor(result, IRREDUCIBLE_POLYNOMIAL);
        }

        return result;
    }

    /**
     * Example usage demonstrating CMAC (Cipher-based Message Authentication Code) computation.
     *
     * @throws Exception If CMAC computation fails.
     * @see Cipher
     * @see SecretKey
     * @see SecretKeySpec
     */
    public static void testCMAC() throws Exception {
        String keyHexadecimal = "2B7E151628AED2A6ABF7158809CF4F3C";
        byte[] keyBytes = CCM.hexStringToByteArray(keyHexadecimal);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        CMAC cmac = new CMAC(secretKey);

        System.out.println("=================== Secret key ===================");
        System.out.println("Key: " + CCM.byteArrayToHexString(keyBytes));
        System.out.println("Sub key 1: " + CCM.byteArrayToHexString(cmac.subKey1));
        System.out.println("Sub key 2: " + CCM.byteArrayToHexString(cmac.subKey2));
        System.out.println("==================================================\n");

        String[] samples = {
                "",
                "6BC1BEE22E409F96E93D7E117393172A",
                "6BC1BEE22E409F96E93D7E117393172AAE2D8A57",
                "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710" // Longer message
        };

        for (int i = 0; i < samples.length; ++i) {
            String sample = samples[i];

            byte[] messageBytes = CCM.hexStringToByteArray(sample);
            byte[] mac = cmac.authentify(messageBytes);

            System.out.println("===================== Sample =====================");
            System.out.println("Message: " + CCM.byteArrayToHexString(messageBytes));
            System.out.println("Tag: " + CCM.byteArrayToHexString(mac));
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

        subKey1 = gfMult(encryptedZeroes);
        subKey2 = gfMult(subKey1);
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
    public byte[] authentify(byte[] message) throws Exception {
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
