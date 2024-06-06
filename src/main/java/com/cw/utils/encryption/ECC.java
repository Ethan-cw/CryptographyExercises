package com.cw.utils.encryption;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.io.File;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;


/**
* @ClassName : ECCKeyPairGenerator
* @Description :  ECC 非对称加密实现
* @Author : Ethan
* @Date: 2023/5/26 10:37
*/
public class ECC {
    private final static String SIGNATURE = "SHA256withECDSA";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    public static void main(String[] args) {
        long seed = 123456789L; // 设置相同的种子
        SecureRandom random = new SecureRandom();
        random.setSeed(seed); // 使用相同的种子
        // 生成随机数
        byte[] randomBytes1 = new byte[16];
        random.nextBytes(randomBytes1);
        System.out.println("Random bytes 1: " + Arrays.toString(randomBytes1));

        // 再次生成随机数
        byte[] randomBytes2 = new byte[16];
        random.nextBytes(randomBytes2);
        System.out.println("Random bytes 2: " + Arrays.toString(randomBytes2));

        try {
            KeyPair keyPair = getKeyPair();
            ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
            ECPrivateKey priKey = (ECPrivateKey) keyPair.getPrivate();
            //System.out.println("[pubKey]:\n" + getPublicKey(keyPair));
            //System.out.println("[priKey]:\n" + getPrivateKey(keyPair));

            //测试文本
            String content = "BMwvqNeivCu4fcqScuQ2U=";

            //加密
            String cipherTxt = encrypt(content.getBytes(), pubKey);
            //解密
            String clearTxt = decrypt(cipherTxt, priKey);

            //打印
            System.out.println("content: " + content);
            System.out.println("cipherTxt[" + cipherTxt.length() + "]: " + cipherTxt);
            System.out.println("clearTxt: " + clearTxt);

            //签名
            String sign = sign(content, priKey);
            //验签
            boolean ret = verify(content, sign, pubKey);
            //打印
            System.out.println("content:" + content);
            System.out.println("sign[" + sign.length() + "]:" + sign);
            System.out.println("verify:" + ret);

        } catch (Exception e) {
            System.out.println("[main]-Exception:" + e.toString());
        }
    }

    //生成秘钥对
    public static KeyPair getKeyPair() throws Exception {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(ecGenSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    //获取公钥(Base64编码)
    public static String getPublicKey(KeyPair keyPair) {
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        byte[] bytes = publicKey.getEncoded();
        return Base64.getEncoder().encodeToString(bytes);
    }

    //获取私钥(Base64编码)
    public static String getPrivateKey(KeyPair keyPair) {
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        byte[] bytes = privateKey.getEncoded();
        return Base64.getEncoder().encodeToString(bytes);
    }

    //公钥加密
    public static String encrypt(byte[] content, ECPublicKey pubKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] encrypted  = cipher.doFinal(content);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    //私钥解密
    public static String decrypt(String content, ECPrivateKey priKey) throws Exception {
        byte[] decode = Base64.getDecoder().decode(content);
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        return new String(cipher.doFinal(decode));
    }

    //私钥签名
    public static String sign(String content, ECPrivateKey priKey){
        //这里可以从证书中解析出签名算法名称
//        Signature signature = Signature.getInstance(getSigAlgName(pubCert));
        Signature signature = null;//"SHA256withECDSA"
        String sign = null;
        try {
            signature = Signature.getInstance(SIGNATURE);
            signature.initSign(priKey);
            signature.update(content.getBytes());
            sign = Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception e) {
            System.out.println(e.toString());
        }
        return sign;
    }

    //公钥验签
    public static boolean verify(String content, String sign, ECPublicKey pubKey){
        //这里可以从证书中解析出签名算法名称
        //Signature signature = Signature.getInstance(getSigAlgName(priCert));
        Signature signature = null; //"SHA256withECDSA"
        boolean verified = false;
        try {
            signature = Signature.getInstance(SIGNATURE);
            signature.initVerify(pubKey);
            signature.update(content.getBytes());
            verified = signature.verify(Base64.getDecoder().decode(sign));
        } catch (Exception e) {
            System.out.println(e.toString());
        }
        return verified;
    }

    /**
     * 解析证书的签名算法，单独一本公钥或者私钥是无法解析的，证书的内容远不止公钥或者私钥
     */
    private static String getSigAlgName(File certFile) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate x509Certificate = (X509Certificate) cf.generateCertificate(Files.newInputStream(certFile.toPath()));
        return x509Certificate.getSigAlgName();
    }
}
