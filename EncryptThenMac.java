import sun.misc.BASE64Decoder;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;





public class Crypto  {


    //declaring variables
    private int mac_sz;
    private SecureRandom r = new SecureRandom();
    private Cipher c;
    private IvParameterSpec IV;
    private SecretKey s_KEY;
    private byte[] digest;
    private String mac_hex="67656F72676564616B6973";
    private boolean bool1=false;




    //Initializing Key and IV
    Crypto() throws  NoSuchAlgorithmException, NoSuchPaddingException {

        c=Cipher.getInstance("AES/CBC/PKCS5Padding");
        generateKEY();
        generateIV();


    }


    //Separtating AES encryption and MAC

    public String datasplitter(String test) throws NoSuchAlgorithmException, IOException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        BASE64Decoder base64decoder = new BASE64Decoder();
        //int macLength = Mac.getInstance("HmacMD5").getMacLength();
        byte[] completeBytes = base64decoder.decodeBuffer(test);
        int macStartIndex = completeBytes.length - mac_sz;

        byte[] encryptedBytes = Arrays.copyOfRange(completeBytes, 0, macStartIndex);
        byte[] computedDigest = Arrays.copyOfRange(completeBytes,macStartIndex,completeBytes.length);

        System.out.print(Arrays.toString(digest));

        System.out.println("Inside datasplitter");
        //authenticate MAC
        if (authenticateMAC(computedDigest)!=true){
            return "no~ne";
        }
        else
        {
            String dec=decrypt(encryptedBytes);
            return dec;

        }




    }


    //get randomIV

    private void generateIV() {

        byte[] newSeed = r.generateSeed(16);
        r.setSeed(newSeed);
        byte[] byteIV = new byte[16];
        r.nextBytes(byteIV);
        IV = new IvParameterSpec(byteIV);

    }

    //get random Key
    private void generateKEY() throws NoSuchAlgorithmException {

        byte[] newSeed = r.generateSeed(32);
        r.setSeed(newSeed);
        KeyGenerator keyGen = KeyGenerator.getInstance("AES"); // A
        SecureRandom sRandom = SecureRandom.getInstanceStrong();
        keyGen.init(256, sRandom);
        s_KEY = keyGen.generateKey();

    }



    //authentication method
    public boolean authenticateMAC(byte[] digested){

        boolean tst=true;
        System.out.print(Arrays.toString(digested));
        System.out.println("\n");
        System.out.print(Arrays.toString(digest));
        for (int x=0; x<digest.length; x++){

            if (digested[x]!=digest[x]){

                System.out.println("ERROR");
                tst=false;

            }
        }
        if (tst!=true){
            System.out.println("MAC failed");
        }
        System.out.println(tst);
        return tst;

    }

    //make the two arrays(AES+MAC), as one.
    public byte[] concatByteArrays(byte[] array1, byte[] array2) {

        byte[] result = new byte[array1.length + array2.length];
        System.arraycopy(array1, 0, result, 0, array1.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);

        return result;
    }

    //MAC creation, using the given hex(mac_hex)
    public byte[] computeMac(byte[] message)
            throws NoSuchAlgorithmException, InvalidKeyException {

        byte[] decodedHexMacKey = DatatypeConverter.parseHexBinary(mac_hex);
        SecretKeySpec secretKeySpc = new SecretKeySpec(decodedHexMacKey, "HmacMD5");
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(secretKeySpc);
        byte[] digested = mac.doFinal(message);
        digest=digested;
        mac_sz=digest.length;

        return digested;
    }



    //AES encryption
    protected byte[] encrypt(String strToEncrypt) throws
            InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException, InvalidKeyException {

        byte[] byteToEncrypt = strToEncrypt.getBytes();
        c.init(Cipher.ENCRYPT_MODE, s_KEY, IV);
        byte[] encryptedBytes = c.doFinal(byteToEncrypt);

        return encryptedBytes;

    }


    //AES Decryption
    protected String decrypt(byte[] byteToDecrypt) throws InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException {

        c.init(Cipher.DECRYPT_MODE, s_KEY, IV);
        byte[] plainByte = c.doFinal(byteToDecrypt);
        String plainText = new String(plainByte);

        return plainText;

    }


}
