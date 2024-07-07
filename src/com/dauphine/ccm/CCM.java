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

    /**
     * Formats the input data for generating the tag.
     *
     * @param nonce          Nonce value for encryption.
     * @param associatedData Associated data.
     * @param plainText      Plaintext to be encrypted.
     * @param tagLength      Length of the tag to be generated.
     * @return Formatted input for tag generation.
     */
    private static byte[] formatInput(byte[] nonce, byte[] associatedData, byte[] plainText, int tagLength) {
        byte[] formattedNonce = new byte[BLOCK_SIZE];
        formattedNonce[0] |= 0x40;

        int tagLengthAdjustment = (tagLength - 2) / 2;
        formattedNonce[0] |= (byte) (((tagLengthAdjustment % 2) + (((tagLengthAdjustment / 2) % 2) * 2) + (((tagLengthAdjustment / 4) % 2)) * 4) * 8);

        int nonceLengthAdjustment = 14 - nonce.length;
        formattedNonce[0] |= (byte) (nonceLengthAdjustment % 2 + ((nonceLengthAdjustment / 2) % 2) * 2 + (((nonceLengthAdjustment / 4) % 2) * 4));

        System.arraycopy(nonce, 0, formattedNonce, 1, nonce.length);

        String plaintextHexadecimalLength = Integer.toHexString(plainText.length);
        byte[] plaintextHexadecimalBytes = Utils.hexadecimalStringToByteArray(plaintextHexadecimalLength);

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
    private static IvParameterSpec formatCounter(byte[] nonce) {
        byte[] formattedIV = new byte[BLOCK_SIZE];
        int nonceLengthAdjustment = 14 - nonce.length;

        formattedIV[0] |= (byte) (nonceLengthAdjustment % 2 + ((nonceLengthAdjustment / 2) % 2) * 2 + (((nonceLengthAdjustment / 4) % 2) * 4));

        System.arraycopy(nonce, 0, formattedIV, 1, nonce.length);

        return new IvParameterSpec(formattedIV);
    }

    /**
     * Example usage demonstrating CCM (Counter with CBC-MAC) mode computation.
     *
     * @param args Command line arguments (not used).
     * @throws Exception If encryption or decryption fails.
     * @see Cipher
     * @see SecretKey
     * @see SecretKeySpec
     */
    public static void main(String[] args) throws Exception {
        String keyHexadecimal = "404142434445464748494A4B4C4D4E4F";
        byte[] keyBytes = Utils.hexadecimalStringToByteArray(keyHexadecimal);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        CCM ccm = new CCM(secretKey);

        System.out.println("=================== Secret key ===================");
        System.out.println("Key: " + Utils.byteArrayToHexadecimalString(keyBytes));
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

            byte[] nonce = Utils.hexadecimalStringToByteArray(nonceHexadecimal);
            byte[] associatedData = Utils.hexadecimalStringToByteArray(associatedDataHexadecimal);
            byte[] plainText = Utils.hexadecimalStringToByteArray(plainTextHexadecimal);

            byte[] cipher = ccm.encryptAndGenerateTag(nonce, associatedData, plainText, tagLength);
            byte[] decrypted = ccm.decryptAndVerifyTag(nonce, associatedData, cipher, tagLength);

            System.out.println("===================== Sample =====================");
            System.out.println("Nonce: " + Utils.byteArrayToHexadecimalString(nonce));
            System.out.println("Associated data: " + Utils.byteArrayToHexadecimalString(associatedData));
            System.out.println("Plain text: " + Utils.byteArrayToHexadecimalString(plainText));
            System.out.println("Tag Length: " + (tagLength * 8) + " bits");
            System.out.println("\nEncrypted Hexadecimal: " + Utils.byteArrayToHexadecimalString(cipher));
            System.out.println("Decrypted Hexadecimal: " + Utils.byteArrayToHexadecimalString(decrypted));
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
    private byte[] generateTag(byte[] nonce, byte[] associatedData, byte[] plainText, int tagLength) throws Exception {
        byte[] formattedInput = formatInput(nonce, associatedData, plainText, tagLength);

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
    public byte[] encryptAndGenerateTag(byte[] nonce, byte[] associatedData, byte[] plainText, int tagLength) throws Exception {
        byte[] authenticationTag = generateTag(nonce, associatedData, plainText, tagLength);
        Cipher aesCipher = Cipher.getInstance("AES/CTR/NoPadding");

        IvParameterSpec counter = formatCounter(nonce);
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
    public byte[] decryptAndVerifyTag(byte[] nonce, byte[] associatedData, byte[] cipher, int tagLength) throws Exception {
        byte[] encryptedText = Arrays.copyOfRange(cipher, 0, cipher.length - tagLength);
        byte[] encryptedTag = Arrays.copyOfRange(cipher, cipher.length - tagLength, cipher.length);

        Cipher aesCipher = Cipher.getInstance("AES/CTR/NoPadding");

        IvParameterSpec counter = formatCounter(nonce);
        aesCipher.init(Cipher.DECRYPT_MODE, secretKey, counter);

        byte[] decryptedTag = aesCipher.doFinal(encryptedTag);

        byte[] incrementedCounter = counter.getIV();
        ++incrementedCounter[incrementedCounter.length - 1];
        IvParameterSpec counterPlus1 = new IvParameterSpec(incrementedCounter);

        aesCipher.init(Cipher.DECRYPT_MODE, secretKey, counterPlus1);
        byte[] decryptedText = aesCipher.doFinal(encryptedText);

        byte[] recalculatedTag = generateTag(nonce, associatedData, decryptedText, tagLength);

        if (Arrays.equals(decryptedTag, recalculatedTag)) {
            return decryptedText;
        }

        return new byte[0];
    }

}
