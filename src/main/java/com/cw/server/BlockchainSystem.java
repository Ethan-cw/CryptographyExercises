package com.cw.server;

import com.cw.enums.KeyTypeEnum;
import com.cw.utils.encryption.RSA;
import com.cw.storage.StorageSystem;
import lombok.extern.slf4j.Slf4j;

import java.math.BigInteger;
import java.util.LinkedList;

/**
 * @ClassName : BlockchainSystem
 * @Description : 区块链系统，接受签名，验证签名，发布消息。
 * @Author : ethan
 * @Date: 2023/5/30  10:34
 */
@Slf4j
public class BlockchainSystem {
    private LinkedList<String> blockchain;
    private StorageSystem storage;
    private static final BigInteger PUBLIC_KEY_E = new BigInteger("65537");

    public BlockchainSystem(StorageSystem system) {
        blockchain = new LinkedList<>();
        storage = system;
    }

    public boolean verifySignature(BigInteger sign, String msg, String groupName) {
        boolean verified;
        String n = storage.get(null, groupName, KeyTypeEnum.PUB_KEY.getType(),
                null, null);
        RSA.SecretKey.PublicKey publicKey = new RSA.SecretKey.PublicKey(
                new BigInteger(n, 16), PUBLIC_KEY_E);
        verified = RSA.verify(sign, msg, publicKey);
        if (verified) {
            log.info("The signature of the group {} is successfully verified and is on the chain!", groupName);
            blockchain.add(msg + " " + sign.toString(16));
        } else {
            log.info("The group {}'s signature verification failed!", groupName);
        }
        return verified;
    }

    public String display() {
        StringBuilder builder = new StringBuilder();
        builder.append("Data that is now on-chain: \n");
        blockchain.forEach(v -> builder.append("- ").append(v).append("\n"));
        return builder.toString();
    }
}
