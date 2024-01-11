package ac.za.nonelela.services;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import static ac.za.nonelela.utils.FileEncryptorConstants.ALGORITHM;
import static ac.za.nonelela.utils.FileEncryptorConstants.TRANSFORMATION;

public class FileEncryptor {
    public static SecretKey generateKey(String password) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(password.getBytes("UTF-8"));
        return new SecretKeySpec(encodedhash, ALGORITHM);
    }
    public  void encrypt(File inputFile, File outputFile, SecretKey key) throws IOException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        try (FileInputStream in = new FileInputStream(inputFile);
             CipherOutputStream out = new CipherOutputStream(new FileOutputStream(outputFile), cipher)) {
            byte[] buffer = new byte[1024];
            int length;
            while ((length = in.read(buffer)) != -1) {
                out.write(buffer, 0, length);
            }
        }
    }
    public  void decrypt(File inputFile, File outputFile, SecretKey key) throws IOException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key);
        try (FileInputStream in = new FileInputStream(inputFile);
             CipherInputStream cin = new CipherInputStream(in, cipher);
             FileOutputStream out = new FileOutputStream(outputFile)) {
            byte[] buffer = new byte[1024];
            int length;
            while ((length = cin.read(buffer)) != -1) {
                out.write(buffer, 0, length);
            }
        }
    }
    public boolean isFileEncrypted(File file) throws IOException {
        RandomAccessFile randomAccessFile = new RandomAccessFile(file, "rw");
        FileChannel fileChannel = randomAccessFile.getChannel();
        FileLock lock = fileChannel.tryLock();
        return lock == null;
    }
}
