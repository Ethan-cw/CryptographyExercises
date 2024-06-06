package com.cw.server;

import com.alibaba.fastjson.JSON;
import com.cw.client.User;
import com.cw.enums.KeyTypeEnum;
import com.cw.enums.MsgTypeEnum;
import com.cw.storage.StorageSystem;
import com.cw.utils.Utils;
import com.cw.utils.encryption.ECC;
import com.cw.utils.encryption.RSA;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;


/**
 * 这个类主要负责与 UDP 有关的收发业务
 * 发送消息
 * 收到UDP消息的后的处理
 */
@Slf4j
public class ServerMsgHandle implements Runnable {
    private static final int BYTE_NUM = 1024;
    private final DatagramSocket socket;
    private final HashMap<String, ArrayList<User>> userManagement; //  登录用户 { group: [u1, u2] }
    private final HashMap<String, BigInteger[]> groupSum;
    private final StorageSystem storage;
    private final HashMap<String, ECPublicKey> eccPubKeys;
    private HashMap<String, AtomicInteger> groupAuthCount;
    private HashMap<String, HashMap<String, UserAuthInfo>> groupAuthInfo;
    private KeyPair keyPair;
    private ECPublicKey pubKey;
    private ECPrivateKey priKey;
    private BlockchainSystem blockchain;
    private boolean isRunning;

    public ServerMsgHandle(DatagramSocket socket, StorageSystem storage, BlockchainSystem blockchain) {
        this.socket = socket;
        this.storage = storage;
        this.blockchain = blockchain;
        isRunning = true;
        userManagement = new HashMap<>();
        eccPubKeys = new HashMap<>();
        groupSum = new HashMap<>();
        groupAuthCount = new HashMap<>();
        groupAuthInfo = new HashMap<>();

        try {
            keyPair = ECC.getKeyPair();
            pubKey = (ECPublicKey) keyPair.getPublic();
            priKey = (ECPrivateKey) keyPair.getPrivate();
        } catch (Exception e) {
            log.error(e.toString());
        }
    }

    public void release() {
        isRunning = false;
        Utils.close(socket);
    }

    @Override
    public void run() {
        while (isRunning) {
            try {
                byte[] container = new byte[BYTE_NUM];
                DatagramPacket packet = new DatagramPacket(container, 0, container.length);
                //3.阻塞式接受包裹
                socket.receive(packet);
                //显示接受数据
                byte[] datas = packet.getData();
                SocketAddress fromAddress = packet.getSocketAddress();
                String data = new String(datas).trim();
                if (!data.equals("")) {
                    String[] s = data.split("@");
                    String actionType = s[0].toUpperCase();
                    if (Utils.enumContains(MsgTypeEnum.class, actionType)) {
                        udpHandle(MsgTypeEnum.valueOf(actionType), s, (InetSocketAddress) fromAddress);
                    }
                }
            } catch (IOException e) {
                log.error(String.valueOf(e));
                release();
            }
        }
    }

    private void udpHandle(MsgTypeEnum type, String[] s, InetSocketAddress fromAddress) {
        switch (type) {
            case AUTH: { // auth@name@encryptAuthInfo
                String name = s[1];
                String encryptAuthInfo = s[2];
                authorization(encryptAuthInfo, eccPubKeys.get(name));
                break;
            }
            case JOIN: {
                String group = s[1];
                String content = s[2];
                addUserToGroup(group, content, fromAddress);
                break;
            }
            case LIST: {
                String group = s[1];
                listGroupUsers(group, fromAddress);
                break;
            }
            case QUERY: {
                String onChainData = blockchain.display();
                Utils.send(socket, fromAddress, MsgTypeEnum.MSG + "@" + onChainData);
                break;
            }
            case SUM: { // BIG@group@num
                String group = s[1];
                String num = s[2];
                BigInteger[] bigIntegers = Utils.stringToBigIntegerArray(num);
                genAndStoreGroupKey(group, bigIntegers);
                break;
            }
            case RE_SUM: {
                String group = s[1];
                String num = s[2];
                BigInteger[] bigIntegers = Utils.stringToBigIntegerArray(num);
                recoverGroupKey(group, bigIntegers);
                break;
            }
            case DELETE: {
                clearAndNotifyUsers();
                break;
            }
            case GET: {  // Utils.send(udpSocket, MPC_ADDRESS, MsgTypeEnum.GET + "@" + host.getName() + "@"  + group + "@" + keyType + "@" + sign(group, keyType));
                String name = s[1];
                String group = s[2];
                String keyType = s[3];
                getRsaKey(s, fromAddress, name, group, keyType);
                break;
            }
            case PUB: {
                String name = s[1];
                String content = s[2];
                setEccPubKeyByName(name, content, fromAddress);
                break;
            }
            default:
                log.error("Unexpected value: " + type);
        }
    }



    /**
     * @Description: 用户授权，对用户信息解密，解密为 group + "@" + host.toJsonString() + "@" + sign(group) + "@" + content;
     * 再加入groupAuthInfo，计数groupAuthCount++。
     * 当同个 groupName 用户授权计数满2个，执行取私钥分片，组成私钥，进行签名操作
     **/
    public void authorization(String encryptInfo, ECPublicKey userPubKey) {
        String info = "";
        String group = "";
        User authUser = null;
        String keyType = "";
        String sign = "";
        String content = "";
        try {
            info = ECC.decrypt(encryptInfo, priKey);
            String[] strings = info.split("@");
            group = strings[0];
            authUser = User.fromJsonString(strings[1]);
            keyType = "d" + authUser.getOrderByGroup(group);
            sign = strings[2];
            content = strings[3];
        } catch (Exception e) {
            System.out.println(e.toString());
        }
        // 私钥需要验证
        boolean verified = ECC.verify(authUser.getName() + group, sign, userPubKey);
        if (!verified) {
            log.info(authUser.getName() + " in group " + group + " failed to authorize signature server");
            return;
        }
        log.info(authUser.getName() + " in group " + group + " authorizes signature server successfully");

        AtomicInteger cnt = groupAuthCount.getOrDefault(group, new AtomicInteger(0));
        UserAuthInfo userInfo = new UserAuthInfo(authUser.getName(), keyType, sign, userPubKey, content);
        HashMap<String, UserAuthInfo> userInfoMap = groupAuthInfo.getOrDefault(group, new HashMap<>());
        userInfoMap.put(authUser.getName(), userInfo);
        groupAuthInfo.put(group, userInfoMap);
        cnt.incrementAndGet();
        groupAuthCount.put(group, cnt);
        if (!(cnt.get() == 2)) return;

        // 执行签名操作， 并发送给区块链
        boolean executed = execute(group);

        // 重置授权
        cnt.set(0);
        groupAuthInfo.get(group).clear();
    }

    /**
     * @Description: 利用授权的组名，拿到已授权用户信息，随后取得各用户私钥碎片并组成私钥，并签名消息发送给区块链系统
     */
    private boolean execute(String group) {
        HashMap<String, UserAuthInfo> usersInfo = groupAuthInfo.get(group);
        StringBuilder recoveredShardings = new StringBuilder();
        StringBuilder msgBuilder = new StringBuilder();
        String rsaN = storage.get(null, group, KeyTypeEnum.PUB_KEY.getType(), null, null);
        String message = "";
        switch (rsaN) {
            case "fail":
                message = "@Not all group users passed the signature verification";
                break;
            case "insufficient":
                message = "@There is not enough data fragment to recover the data, please restore the key";
                break;
            default:
                message = "@Your " + group + " signed message is on the blockchain";
                break;
        }
        //通知组内所有用户信息
        for (User u : userManagement.get(group)) {
            Utils.send(socket, u.getAddress(), MsgTypeEnum.MSG + message);
        }
        if (rsaN.equals("fail") || rsaN.equals("insufficient")) {
            return false;
        }
        usersInfo.forEach((userName, userInfo) -> {
            // 取数据
            String sharding = storage.get(userName, group, userInfo.getDataType(), userInfo.getSign(), userInfo.getUserPubKey());
            int idx = Integer.parseInt(String.valueOf(userInfo.getDataType().charAt(1)));
            if (idx == 0) {
                recoveredShardings.insert(idx, sharding);
                msgBuilder.insert(idx, userInfo.getMsg());
            } else {
                recoveredShardings.append(sharding);
                msgBuilder.append(userInfo.getMsg());
            }
        });
        String rsaD = recoveredShardings.toString();
        String msg = msgBuilder.toString();
        RSA.SecretKey.PrivateKey privateKey = new RSA.SecretKey.PrivateKey(
                new BigInteger(rsaN, 16),
                new BigInteger(rsaD, 16));
        log.debug("Signature server recovery {}'s {}", group, privateKey);
        BigInteger sign = RSA.sign(msg, privateKey);

        return blockchain.verifySignature(sign, msg, group);
    }

    private void clearAndNotifyUsers() {
        storage.deleteOneDataBase();
        // 遍历所有用户并去重
        Set<User> uniqueUsers = new HashSet<>();
        for (ArrayList<User> userList : userManagement.values()) {
            uniqueUsers.addAll(userList);
        }
        // 通知
        for (User user : uniqueUsers) {
            Utils.send(socket, user.getAddress(), MsgTypeEnum.MSG + "@" + "One of the databases is invalid");
        }
        log.info("————————————————————————————— After randomly deleting a database —————————————————————————————————————");
        storage.display();
    }

    private void getRsaKey(String[] s, InetSocketAddress fromAddress, String name, String group, String keyType) {
        if (KeyTypeEnum.isPubKey(keyType)) {
            String publicKeyN = storage.get(null, group, keyType, null, null); // 取公钥不需要验证
            if (publicKeyN.isEmpty()) {
                Utils.send(socket, fromAddress, MsgTypeEnum.MSG + "@" + "Failed to fetch the public key");
            } else {
                Utils.send(socket, fromAddress, MsgTypeEnum.MSG + "@group-" + group + ": PubKey-" + publicKeyN);
            }
        } else if (KeyTypeEnum.isPriKey(keyType)) {
            String sign = s[4];
            String userPriK = storage.get(name, group, keyType, sign, eccPubKeys.get(name));
            if (userPriK.isEmpty()) {
                Utils.send(socket, fromAddress, MsgTypeEnum.MSG + "@" + "Failed to fetch the private key shard");
            } else {
                Utils.send(socket, fromAddress, MsgTypeEnum.MSG + "@group-" + group + ": PriKey sharding-" + userPriK);
            }
        }
    }

    private void setEccPubKeyByName(String name, String content, InetSocketAddress fromAddress) {
        byte[] pubKeyBytes = Base64.getDecoder().decode(content);
        try {
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            ECPublicKey ecc = (ECPublicKey) keyFactory.generatePublic(pubKeySpec);
            eccPubKeys.put(name, ecc);
            String pubKeyStr = Base64.getEncoder().encodeToString(pubKey.getEncoded());
            Utils.send(socket, fromAddress, MsgTypeEnum.PUB + "@" + "server" + "@" + pubKeyStr);
            log.info("User {} is already connected.", name);
        } catch (Exception e) {
            log.error(e.toString());
        }
    }

    private void listGroupUsers(String group, InetSocketAddress fromAddress) {
        ArrayList<User> groupList = userManagement.getOrDefault(group, new ArrayList<>());
        if (groupList.isEmpty()) {
            Utils.send(socket, fromAddress, MsgTypeEnum.MSG + "@This group does not have any logged-in users");
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append("This group of online users includes:\n");
            for (User u : groupList) {
                sb.append("- ").append(u).append("\n");
            }
            Utils.send(socket, fromAddress, MsgTypeEnum.MSG + "@" + sb);
        }
    }

    private void addUserToGroup(String group, String content, InetSocketAddress fromAddress) {
        User fromUser = JSON.parseObject(content, User.class);
        ArrayList<User> list = userManagement.getOrDefault(group, new ArrayList<>());
        int curGroupSize = list.size();
        if (curGroupSize >= 2) {
            Utils.send(socket, fromAddress, MsgTypeEnum.MSG + "@This group of users is full");
            return;
        }
        fromUser.putOrderByGroup(group, curGroupSize);
        list.add(fromUser);
        userManagement.put(group, list);
        log.info("User {} joins the group {} in the order:{}.", fromUser, group, curGroupSize);

        // 将 fromUser在 group 组内的顺序发给 fromUser
        Utils.send(socket, fromAddress, MsgTypeEnum.ORDER + "@" + group + "@" + curGroupSize);

        //通知组内所有用户 fromUser 已经在线
        for (User u : list) {
            Utils.send(socket, u.getAddress(), MsgTypeEnum.MSG + "@User " + fromUser + " successfully joined the group " + group + " in the order:" + curGroupSize);
        }

        // 使得 组内成员 互为好友
        for (User u : list) {
            if (!u.equals(fromUser)) {
                Utils.send(socket, fromAddress, MsgTypeEnum.FRIEND + "@" + group + "@" + u.toJsonString());
                Utils.send(socket, u.getAddress(), MsgTypeEnum.FRIEND + "@" + group + "@" + fromUser.toJsonString());
            }
        }
    }

    public BigInteger[] getD1AndD2(BigInteger[] diffsSum, BigInteger[] rsSum) {
        BigInteger D1 = diffsSum[0].add(rsSum[0]);
        BigInteger D2 = diffsSum[1].add(rsSum[1]);
        return new BigInteger[]{D1, D2};
    }

    // 得到同组的两位用户的大小数，则开始产生 组的 rsa 秘钥并保存
    private void genAndStoreGroupKey(String group, BigInteger[] bigIntegers) {
        if (!groupSum.containsKey(group)) {
            groupSum.put(group, bigIntegers);
            return;
        }
        BigInteger[] d1AndD2 = getD1AndD2(groupSum.get(group), bigIntegers);
        BigInteger p = d1AndD2[0].shiftLeft(1024 - d1AndD2[0].bitLength());
        BigInteger q = d1AndD2[1].shiftLeft(1024 - d1AndD2[1].bitLength());
        RSA.SecretKey groupKey = RSA.generateKeyByD1AndD2(p, q);
        RSA.SecretKey.PublicKey publicKey = groupKey.getPublicKey();
        RSA.SecretKey.PrivateKey privateKey = groupKey.getPrivateKey();

        log.debug("n = {}", privateKey.n.toString(16));
        log.debug("d = {}", privateKey.d.toString(16));

        // 公钥存入存储系统，私钥分成碎片存入存储系统
        storage.put(publicKey.n.toString(16), group, KeyTypeEnum.PUB_KEY);

        // pks 私钥碎片
        String[] pks = Utils.splitString(privateKey.d.toString(16), 2);

        // 私钥碎片存入 storage
        for (int i = 0; i < pks.length; i++) {
            storage.put(pks[i], group, KeyTypeEnum.getByType("d" + i));
        }
        storage.display();

        for (User u : userManagement.get(group)) {
            Utils.send(socket, u.getAddress(), MsgTypeEnum.MSG + "@The group RSA key is successfully generated and saved to the storage");
        }

        // 清除信息
        groupSum.remove(group);
    }

    private void recoverGroupKey(String group, BigInteger[] bigIntegers) {
        if (!groupSum.containsKey(group)) {
            groupSum.put(group, bigIntegers);
            return;
        }
        BigInteger[] d1AndD2 = getD1AndD2(groupSum.get(group), bigIntegers);
        BigInteger p = d1AndD2[0].shiftLeft(1024 - d1AndD2[0].bitLength());
        BigInteger q = d1AndD2[1].shiftLeft(1024 - d1AndD2[1].bitLength());
        RSA.SecretKey groupKey = RSA.generateKeyByD1AndD2(p, q);
        RSA.SecretKey.PublicKey publicKey = groupKey.getPublicKey();
        RSA.SecretKey.PrivateKey privateKey = groupKey.getPrivateKey();

        log.info("n = {}", privateKey.n.toString(16));
        log.info("d = {}", privateKey.d.toString(16));


        // 公钥存入存储系统，私钥分成碎片存入存储系统
        boolean recover = storage.recover(publicKey.n.toString(16), group, KeyTypeEnum.PUB_KEY);
        if (!recover){
            for (User u : userManagement.get(group)) {
                Utils.send(socket, u.getAddress(), MsgTypeEnum.MSG + "@The root key was entered incorrectly and the group RSA recovery failed");
            }
            return;
        }


        // pks 私钥碎片
        String[] pks = Utils.splitString(privateKey.d.toString(16), 2);

        // 私钥碎片存入 storage
        for (int i = 0; i < pks.length; i++) {
            storage.recover(pks[i], group, KeyTypeEnum.getByType("d" + i));
        }
        storage.display();

        for (User u : userManagement.get(group)) {
            Utils.send(socket, u.getAddress(), MsgTypeEnum.MSG + "@The group RSA key is successfully recovered to the storage");
        }

        groupSum.remove(group);
    }
}
