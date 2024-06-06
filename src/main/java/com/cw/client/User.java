package com.cw.client;


import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.TypeReference;
import com.alibaba.fastjson.annotation.JSONField;
import com.cw.utils.Utils;
import com.cw.utils.encryption.ECC;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import javax.swing.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;


@Slf4j
public class User {

    @Getter
    private final String name;

    @Getter
    private final String ip;

    @Getter
    private final int port;

    @JSONField(serialize = false)
    private KeyPair keyPair;

    @JSONField(serialize = false)
    @Getter
    private ECPublicKey pubKey;

    @JSONField(serialize = false)
    @Getter
    private ECPrivateKey priKey;
    @JSONField(serialize = false)
    private BigInteger R128bits1;
    @JSONField(serialize = false)
    private BigInteger R128bits2;
    @JSONField(serialize = false)
    @Getter
    @Setter
    private long[] signNum;  // [d1, d2] 该用户 d1 和 d2，其中 d1 > d2
    @JSONField(serialize = false)
    private HashMap<String, User> groupFriends; // 保存同个 group 的 上线好友

    @JSONField(serialize = false)
    @Getter
    @Setter
    private ECPublicKey serverPubKey;
    public HashMap<String, Integer> groupOrder; // 用户在 group 的位置, 0 or 1

    public User(String name, String ip, int port) {
        this.name = name;
        this.ip = ip;
        this.port = port;
        groupOrder = new HashMap<>();
        groupFriends = new HashMap<>();

        R128bits1 = new BigInteger(Utils.Random128bit());
        R128bits2 = new BigInteger(Utils.Random128bit());

        try {
            keyPair = ECC.getKeyPair();
            pubKey = (ECPublicKey) keyPair.getPublic();
            priKey = (ECPrivateKey) keyPair.getPrivate();
            log.info(name + " ECC public key: " + ECC.getPublicKey(keyPair));
            log.info(name + " ECC private key: " + ECC.getPrivateKey(keyPair));
        } catch (Exception e) {
            System.out.println("[user]-getKeyPair:" + e.toString());
        }
    }

    public User(String name, String ip, int port, HashMap<String, Integer> groupOrder) {
        this.name = name;
        this.ip = ip;
        this.port = port;
        this.groupOrder = groupOrder;
    }

    public String toJsonString() {
        return JSON.toJSONString(this);
    }

    public static User fromJsonString(String jsonString) {
        JSONObject object = JSON.parseObject(jsonString);
        TypeReference<HashMap<String, Integer>> typeRef = new TypeReference<HashMap<String, Integer>>() {
        };
        HashMap<String, Integer> groupOrder = JSON.parseObject(object.getString("groupOrder"), typeRef);
        return new User(object.getString("name"), object.getString("ip"), object.getInteger("port"), groupOrder);
    }

    public void addFriend(String group, User f) {
        groupFriends.put(group, f);
    }

    public boolean isOnline(String group) {
        return groupFriends.containsKey(group);
    }

    public User getFriend(String group) {
        return groupFriends.get(group);
    }

    public void putOrderByGroup(String group, Integer order) {
        groupOrder.put(group, order);
    }

    public Integer getOrderByGroup(String group) {
        return groupOrder.get(group);
    }

    //返回两个随机数
    public BigInteger[] getRs() {
        return new BigInteger[]{R128bits1, R128bits2};
    }

    /**
     * @Description: 以用户A为例 计算 A diffs = [dA1-rA1, dA2-rA2]
     **/
    public BigInteger[] getDiffs() {
        if (signNum == null) return new BigInteger[]{BigInteger.ZERO, BigInteger.ZERO};
        BigInteger d1 = new BigInteger(String.valueOf(signNum[0])).subtract(R128bits1);
        BigInteger d2 = new BigInteger(String.valueOf(signNum[1])).subtract(R128bits2);
        return new BigInteger[]{d1, d2};
    }

    /**
     * @Description: 计算用户A和B为例，A接收到B的随机数 计算 RsSum = [rA1 +rB1 , rA2 + rB2]
     **/
    public BigInteger[] getRsSum(BigInteger[] otherRs) {
        BigInteger s1 = otherRs[0].add(R128bits1);
        BigInteger s2 = otherRs[1].add(R128bits2);
        return new BigInteger[]{s1, s2};
    }

    /**
     * @Description: 以用户A，B为例，A接收到B的otherDiff，计算 A diff 与 otherDiff 两者之和
     **/
    public BigInteger[] getDiffsSum(BigInteger[] otherDiff) {
        BigInteger[] diffs = getDiffs();
        BigInteger s1 = otherDiff[0].add(diffs[0]);
        BigInteger s2 = otherDiff[1].add(diffs[1]);
        return new BigInteger[]{s1, s2};
    }

    @Override
    public String toString() {
        return name + " " + ip + ":" + port;
    }

    public InetSocketAddress getAddress() {
        return new InetSocketAddress(ip, port);
    }



    public static void main(String[] args) {
        JTextField textField = new JTextField();
        Object[] message = {
                "Please re-enter key and enigma status:", textField
        };

        int option = JOptionPane.showConfirmDialog(null, message, "'s request to recover RSA key pairs",
                JOptionPane.YES_NO_OPTION);

        if (option == JOptionPane.OK_OPTION) {
            String text = textField.getText();
            System.out.println("Input text: " + text);
        }
    }

}
