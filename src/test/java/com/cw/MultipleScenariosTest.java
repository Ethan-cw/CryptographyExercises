//package com.cw;
//
//
//import com.cw.utils.encryption.RSA;
//import com.cw.signserver.TrustedSignatureServer;
//import com.cw.storage.StorageSystem;
//import com.cw.client.Client;
//import com.cw.utils.Utils;
//import lombok.extern.slf4j.Slf4j;
//import org.junit.jupiter.api.Assertions;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//
//import java.security.interfaces.ECPublicKey;
//
//@Slf4j
//public class MultipleScenariosTest {
//    private static final StorageSystem storage = new StorageSystem();
//    private static final BlockchainSystem bcSystem = new BlockchainSystem(storage);
//    private static final TrustedSignatureServer signatureServer = new TrustedSignatureServer(storage, bcSystem);
//    private static String group;
//    private static Client clientA;
//    private static Client clientB;
//    private static RSA.SecretKey usersRsaKeyPair;
//
//    /**
//     * @Description:  用户A, B登录，通过MPC混淆加密，生成RSA秘钥对，将公钥和分片后的私钥存入数据库。存储方式为2+1冗余存储。
//     **/
//    @BeforeEach
//    public void usersLogin(){
//        log.info("The test begins by generating an RSA key pair of a user group and storing them in the database ");
//        group = "AB";
//        group = Utils.getSha256Str(group);
//
//        log.info("用户 A 的 enigma 机状态数(小于62)和8位字符的key为：3 4 5 qqqqwwww");
//        clientA = MultipleScenarios.userLogin("A", "3 4 5 qqqqwwww", group);
//
//        log.info("用户 B 的 enigma 机状态数(小于62)和8位字符的key为：7 8 9 xxxxyyyy");
//        clientB = MultipleScenarios.userLogin("B", "7 8 9 xxxxyyyy", group);
//
//        clientA.setDataType("d0");
//        clientB.setDataType("d1");
//
//        usersRsaKeyPair = MultipleScenarios.getUserSecretKey(group, clientA, clientB);
//        RSA.SecretKey.PublicKey publicKey = usersRsaKeyPair.getPublicKey();
//        RSA.SecretKey.PrivateKey privateKey = usersRsaKeyPair.getPrivateKey();
//        // 公钥存入存储系统，私钥分成碎片存入存储系统
//        storage.put(publicKey.n.toString(16), group, "n");
//        String[] pks = Utils.splitString(privateKey.d.toString(16), 2);
//        for (int i = 0; i < pks.length; i++) {
//            storage.put(pks[i], group, "d" + i);
//        }
//        // 展示存储系统数据
//        log.info("The original database: ");
//        storage.display();
//    }
//
//
//    @Test
//    public void scenarioOneTest() {
//        log.info("*************************** At the beginning of the scenario one *************************************");
//        RSA.SecretKey.PublicKey publicKey = usersRsaKeyPair.getPublicKey();
//        RSA.SecretKey.PrivateKey privateKey = usersRsaKeyPair.getPrivateKey();
//        log.info("After randomly deleting a database");
//        storage.deleteOneDataBase();
//        storage.display();
//
//        String refactoredPubKeyN = storage.get(null, group, "n", null, null); //公钥不需要验证
//        StringBuilder refactoredPriKeyD = new StringBuilder();
//
//        String ASign = clientA.sign(group);
//        String APriK = storage.get(clientA.getName(), group, clientA.getDataType(), ASign, clientA.getPubKey());
//        if (!APriK.isEmpty()) {
//            refactoredPriKeyD.append(APriK);
//        }
//
//        String BSign = clientB.sign(group);
//        String BPriK = storage.get(clientB.getName(), group, clientB.getDataType(), BSign, clientB.getPubKey());
//        if (!BPriK.isEmpty()) {
//            refactoredPriKeyD.append(BPriK);
//        }
//        Assertions.assertEquals(publicKey.n.toString(16), refactoredPubKeyN);
//        Assertions.assertEquals(privateKey.d.toString(16), refactoredPriKeyD.toString());
//
//        log.info("Refactored n of public key: " + refactoredPubKeyN);
//        log.info("The public key is rebuilt successfully: {}", refactoredPubKeyN.equals(publicKey.n.toString(16)));
//
//        log.info("Refactored d of private key: " + refactoredPriKeyD);
//        log.info("The private key is rebuilt successfully: {}", refactoredPriKeyD.toString().equals(privateKey.d.toString(16)));
//        log.info("*************************** The scenario one is over *************************************");
//    }
//
//
//    /**
//     * @Description: 场景二测试，两个用户授权 Signature Server，
//     **/
//    @Test
//    public void scenarioTwoTest(){
//        log.info("*************************** The scenario two : users start authorizing signature server *************************************");
//        ECPublicKey serverPubKey = signatureServer.getPublicKey();
//        String AEncryptInfo = clientA.encryptInformation(group, serverPubKey);
//        String BEncryptInfo = clientB.encryptInformation(group, serverPubKey);
//
//        signatureServer.authorization(AEncryptInfo, clientA.getPubKey());
//        signatureServer.authorization(BEncryptInfo, clientB.getPubKey());
//        log.info("*************************** The scenario two is over *************************************");
//    }
//
//
//    /**
//     * @Description:  测试场景三，删除两个数据库，3个数据库只有一个数据库存在数据，用户输入正确的key恢复数据。
//     **/
//    @Test
//    public void succeedingScenarioThreeTest() {
//        log.info("*************************** At the beginning of the succeeding scenario three *************************************");
//
//        RSA.SecretKey.PublicKey publicKey = usersRsaKeyPair.getPublicKey();
//        RSA.SecretKey.PrivateKey privateKey = usersRsaKeyPair.getPrivateKey();
//        log.info("After randomly deleting two databases");
//        storage.deleteOneDataBase();
//        storage.deleteOneDataBase();
//        storage.display();
//
//        // 恢复公钥
//        storage.recover(publicKey.n.toString(16), group, "n");
//
//        // 恢复私钥碎片
//        String[] pks = Utils.splitString(privateKey.d.toString(16), 2);
//        for (int i = 0; i < pks.length; i++) {
//            storage.recover(pks[i], group, "d" + i);
//        }
//        // 展示存储系统数据
//        log.info("The restored database: ");
//        storage.display();
//    }
//
//    /**
//     * @Description:  测试场景三，删除两个数据库，3个数据库只有一个数据库存在数据，用户输错key，数据库恢复失败
//     **/
//    @Test
//    public void failingScenarioThreeTest() {
//        log.info("*************************** At the beginning of the failing scenario three *************************************");
//        Client wrongClientA = MultipleScenarios.userLogin("A", "3 4 5 wwwwoooo", group);
//        RSA.SecretKey wrongKey = MultipleScenarios.getUserSecretKey(group, wrongClientA, clientB);
//
//        RSA.SecretKey.PublicKey publicKey = wrongKey.getPublicKey();
//        RSA.SecretKey.PrivateKey privateKey = wrongKey.getPrivateKey();
//        log.info("After randomly deleting two databases");
//        storage.deleteOneDataBase();
//        storage.deleteOneDataBase();
//        storage.display();
//
//        // 恢复公钥
//        storage.recover(publicKey.n.toString(16), group, "n");
//
//        // 恢复私钥碎片
//        String[] pks = Utils.splitString(privateKey.d.toString(16), 2);
//        for (int i = 0; i < pks.length; i++) {
//            storage.recover(pks[i], group, "d" + i);
//        }
//        // 展示存储系统数据
//        log.info("The restored database: ");
//        storage.display();
//    }
//
//    public static void main(String[] args) {
//        MultipleScenariosTest test = new MultipleScenariosTest();
//        test.usersLogin();
//        test.scenarioOneTest();
//
//        test.usersLogin();
//        test.scenarioTwoTest();
//
//        test.usersLogin();
//        test.failingScenarioThreeTest();
//
//        test.usersLogin();
//        test.succeedingScenarioThreeTest();
//    }
//}