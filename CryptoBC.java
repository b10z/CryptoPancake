
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


public class Crypto {

    private DbHelper newDB;
    private SecretKey secret;

    //initial keys production, using Username, and Password
    public boolean encr(String user, String pass) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidCipherTextException, UnsupportedEncodingException {

        KeyParameter key1=KeyGen(user, pass, 2000);
        KeyParameter params2 = KeyGen(user, pass, 1000, key1);
        String authHash= Arrays.toString(params2.getKey());



        newDB=new DbHelper();


        if (!newDB.Insert_db(user, authHash)) {
           return false;
        } else {
               return true;
        }


    }
    
//Production of keys, to check if password is correct
    public boolean Auth_pass(String user, String pass, Context context) {


        KeyParameter key1=KeyGen(user, pass, 2000);
        KeyParameter params2 = KeyGen(user, pass, 1000, key1);


        String authHash= Arrays.toString(params2.getKey());
        newDB=new DbHelper();


        if (!newDB.AuthCheck(user, authHash)) {
            return false;
        } else {
            return true;
        }


    }
//hashing the data
    public boolean DataHasher(String user, String pass, int it, String data) throws Exception {
        KeyParameter newKey=KeyGen(user,pass,1000);
        String authHash= Arrays.toString(newKey.getKey());
        String encrypted_stuff=encrypt(data,authHash);
        System.out.println(encrypted_stuff);
        newDB=new DbHelper();
        newDB.Data_Register(user,encrypted_stuff);
        return true;
    }


//Key Creation methods
    public KeyParameter KeyGen(String user, String pass, int it, KeyParameter m){
        byte[] passKey= PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(pass.toCharArray());
        byte[] userb=PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(user.toCharArray());


        PBEParametersGenerator authgen=new PKCS5S2ParametersGenerator();
        authgen.init(m.getKey(),passKey, 1000);
        KeyParameter params2 = (KeyParameter)authgen.generateDerivedParameters(128);
        return params2;

    }

    public KeyParameter KeyGen(String user, String pass, int it){
        byte[] passKey= PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(pass.toCharArray());
        byte[] userb=PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(user.toCharArray());

        PBEParametersGenerator gen= new PKCS5S2ParametersGenerator();
        gen.init(passKey, userb, it);
        KeyParameter params = (KeyParameter)gen.generateDerivedParameters(128);
        return params;

    }




//encrypt text, using key
    public String encrypt(String word, String authHash) throws Exception {


        byte[] ivBytes;
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[20];
        random.nextBytes(bytes);
        byte[] saltBytes = bytes;
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(authHash.toCharArray(),saltBytes,65556,256);
        SecretKey secretKey = factory.generateSecret(spec);
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        AlgorithmParameters params = cipher.getParameters();
        ivBytes =   params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] encryptedTextBytes = cipher.doFinal(word.getBytes("UTF-8"));

        byte[] buffer = new byte[saltBytes.length + ivBytes.length + encryptedTextBytes.length];
        System.arraycopy(saltBytes, 0, buffer, 0, saltBytes.length);
        System.arraycopy(ivBytes, 0, buffer, saltBytes.length, ivBytes.length);
        System.arraycopy(encryptedTextBytes, 0, buffer, saltBytes.length + ivBytes.length, encryptedTextBytes.length);
        String finale=Base64.encodeToString(buffer,Base64.NO_WRAP);
        return finale;
    }

    //decrypt text, using key
    public String decrypt(String encryptedText, String authHash) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] decryptedTextBytes = null;
        try {
            ByteBuffer buffer = ByteBuffer.wrap(Base64.decode(encryptedText, Base64.NO_WRAP));
            byte[] saltBytes = new byte[20];
            buffer.get(saltBytes, 0, saltBytes.length);
            byte[] ivBytes1 = new byte[cipher.getBlockSize()];
            buffer.get(ivBytes1, 0, ivBytes1.length);
            byte[] encryptedTextBytes = new byte[buffer.capacity() - saltBytes.length - ivBytes1.length];

            buffer.get(encryptedTextBytes);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(authHash.toCharArray(), saltBytes, 65556, 256);
        SecretKey secretKey = factory.generateSecret(spec);
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes1));

        try {
            decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
    }
        catch(Exception e){
        System.out.println(e);
    }

        return new String(decryptedTextBytes);
    }


}


