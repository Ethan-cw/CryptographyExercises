package com.cw.storage;

import com.cw.enums.KeyTypeEnum;
import com.cw.storage.reedsolomon.ReedSolomon;
import com.cw.utils.encryption.ECC;
import lombok.extern.slf4j.Slf4j;

import java.nio.ByteBuffer;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Random;

/**
 * @ClassName : storageSystem
 * @Description : 存储运营商
 * @Author : Ethan
 * @Date: 2023/5/24  15:34
 */
@Slf4j
public class StorageSystem {
    private static final int DATA_SHARDS = 2;
    private static final int PARITY_SHARDS = 1;
    private static final int TOTAL_SHARDS = 3;
    private static final int BYTES_IN_INT = 4;

    // 模拟3个数据库： i 数据库编号: { groupName ： {data ： dataType}}
    private final ArrayList<HashMap<String, HashMap<String, byte[]>>> dataBaseManagement;

    public StorageSystem() {
        dataBaseManagement = new ArrayList<>(TOTAL_SHARDS);
        for (int i = 0; i < TOTAL_SHARDS; i++) {
            dataBaseManagement.add(new HashMap<>());
        }
    }

    /**
     * @Description: 模拟删一个非空的数据库
     **/
    public void deleteOneDataBase() {
        Random random = new Random();
        int idx = random.nextInt(3);
        if (dataBaseManagement.get(idx).isEmpty()) {
            idx = random.nextInt(3);
        }
        dataBaseManagement.get(idx).clear();
    }

    /**
     * @Description:  打印数据库的当前情况
     **/
    public void display() {
        for (int i = 0; i < TOTAL_SHARDS; i++) {
            HashMap<String, HashMap<String, byte[]>> groupData = dataBaseManagement.get(i);
            System.out.println("-------------- " + i + " database -------------");
            if (groupData.isEmpty()) {
                System.out.println("this database is empty");
            } else {
                groupData.forEach((group, map) -> {
                    System.out.print("group " + group + " : ");
                    map.forEach((k, v) -> System.out.print(k + " "));
                    System.out.println();
                });
            }
        }
        System.out.println("----------------------------------------------------");
    }

    /**
     * 通过 userName、signGroupName 和 keyType 取 公钥 或者 私钥碎片。
     * 不同在于取私钥碎片需要验签
     * 当 DATA_SHARDS 至多少了 PARITY_SHARDS 个时，可通过 ReedSolomon 恢复出来。
     **/
    public String get(String userName, String signGroupName, String keyType, String sign, ECPublicKey userPubKey) {
        boolean verified = false;
        // 私钥需要验签，公钥不需要
        if (KeyTypeEnum.isPriKey(keyType)) {
            verified = ECC.verify(userName + signGroupName, sign, userPubKey);
            if (verified) {
                log.info("When fetching data, storage verifies that user {} succeeds ", userName);
            } else {
                log.info("When fetching data, storage fails to authenticate user {} ", userName);
                return "fail";
            }
        }

        // 取得所有的 DATA_SHARDS
        byte[][] shards = new byte[TOTAL_SHARDS][];
        boolean[] shardPresent = new boolean[TOTAL_SHARDS];
        int shardSize = 0;
        int shardCount = 0;
        for (int i = 0; i < TOTAL_SHARDS; i++) {
            HashMap<String, byte[]> groupMap = dataBaseManagement.get(i).getOrDefault(signGroupName, new HashMap<>());
            if (groupMap.isEmpty()) continue;
            byte[] bytes = groupMap.getOrDefault(keyType, new byte[0]);
            if (bytes.length > 0) {
                shardSize = bytes.length;
                shards[i] = new byte[shardSize];
                shardPresent[i] = true;
                shardCount += 1;
                System.arraycopy(bytes, 0, shards[i], 0, shardSize);
            }
        }

        // We need at least DATA_SHARDS to be able to reconstruct the data.
        if (shardCount < DATA_SHARDS) {
            log.info("Not enough shards present");
            return "insufficient";
        }

        // Make empty buffers for the missing shards.
        for (int i = 0; i < TOTAL_SHARDS; i++) {
            if (!shardPresent[i]) {
                shards[i] = new byte[shardSize];
            }
        }

        // Use Reed-Solomon to fill in the missing shards
        ReedSolomon reedSolomon = ReedSolomon.create(DATA_SHARDS, PARITY_SHARDS);
        reedSolomon.decodeMissing(shards, shardPresent, 0, shardSize);

        // Combine the data shards into one buffer for convenience.
        // (This is not efficient, but it is convenient.)
        byte[] allBytes = new byte[shardSize * DATA_SHARDS];
        for (int i = 0; i < DATA_SHARDS; i++) {
            System.arraycopy(shards[i], 0, allBytes, shardSize * i, shardSize);
        }
        int dataSize = ByteBuffer.wrap(allBytes).getInt();

        return new String(allBytes, BYTES_IN_INT, dataSize);
    }

    /**
     * 通过 signGroupName 和 dataType 存 公钥 或者 私钥碎片， 将其分 2+1 个 shards 存储。
     **/
    public void put(String data, String signGroupName, KeyTypeEnum keyType) {
        int dataSize = data.length();
        int storedSize = dataSize + BYTES_IN_INT;
        int shardSize = (storedSize + DATA_SHARDS - 1) / DATA_SHARDS;
        int bufferSize = shardSize * DATA_SHARDS;
        ByteBuffer buffer = ByteBuffer.allocate(bufferSize);

        buffer.putInt(dataSize);
        buffer.put(data.getBytes());

        byte[][] shards = new byte[TOTAL_SHARDS][shardSize];

        // Fill in the data shards
        for (int i = 0; i < DATA_SHARDS; i++) {
            System.arraycopy(buffer.array(), i * shardSize, shards[i], 0, shardSize);
        }

        // Use Reed-Solomon to calculate the parity.
        ReedSolomon reedSolomon = ReedSolomon.create(DATA_SHARDS, PARITY_SHARDS);
        reedSolomon.encodeParity(shards, 0, shardSize);

        storeShardsByGroup(signGroupName, keyType, shards);
        buffer.clear();
    }

    /**
     * @Description:  将 shards[i] 分别存入第i个数据库
     **/
    private void storeShardsByGroup(String signGroupName, KeyTypeEnum keyType, byte[][] shards) {
        for (int i = 0; i < TOTAL_SHARDS; i++) {
            HashMap<String, byte[]> groupMap = dataBaseManagement.get(i).getOrDefault(signGroupName, new HashMap<>());
            groupMap.put(keyType.getType(), shards[i]);
            dataBaseManagement.get(i).put(signGroupName, groupMap);
        }
    }


    /**
     * @param data          秘钥数据
     * @param signGroupName 组名的密文
     * @param keyType       n代表公钥 d0和d1 代表私钥碎片
     * @return
     * @Description: 根据 signGroupName 和 keyType 恢复 秘钥数据的可靠性存储
     * 1. 先判断仅剩的一个数据库中的公钥（秘钥碎片）的分片与用户再次输入key得到秘钥分片是否相同；
     * 2. 相同则用户输入key正确，重新存入公钥（秘钥碎片）的分片，恢复成功；
     * 3. 否则提示输入key错误，恢复失败。
     */
    public boolean recover(String data, String signGroupName, KeyTypeEnum keyType) {
        int dataSize = data.length();
        int storedSize = dataSize + BYTES_IN_INT;
        int shardSize = (storedSize + DATA_SHARDS - 1) / DATA_SHARDS;
        int bufferSize = shardSize * DATA_SHARDS;
        ByteBuffer buffer = ByteBuffer.allocate(bufferSize);

        buffer.putInt(dataSize);
        buffer.put(data.getBytes());

        byte[][] shards = new byte[TOTAL_SHARDS][shardSize];

        // Fill in the data shards
        for (int i = 0; i < DATA_SHARDS; i++) {
            System.arraycopy(buffer.array(), i * shardSize, shards[i], 0, shardSize);
        }

        // Use Reed-Solomon to calculate the parity.
        ReedSolomon reedSolomon = ReedSolomon.create(DATA_SHARDS, PARITY_SHARDS);
        reedSolomon.encodeParity(shards, 0, shardSize);

        boolean validation = false;
        for (int i = 0; i < TOTAL_SHARDS; i++) {
            HashMap<String, byte[]> groupMap = dataBaseManagement.get(i).getOrDefault(signGroupName, new HashMap<>());
            if (!groupMap.isEmpty() && groupMap.getOrDefault(keyType.getType(), new byte[0]).length>0) {
                validation = Arrays.equals(groupMap.get(keyType.getType()), shards[i]);
                break;
            }
        }
        if (validation) {
            storeShardsByGroup(signGroupName, keyType, shards);
            log.info("The key entered by group {} is correct, and the {} recovery is successful.", signGroupName, keyType.getType());
        } else {
            log.info("The key entered by group {} is incorrect, and the {} recovery fails.", signGroupName, keyType.getType());
        }

        buffer.clear();

        return validation;
    }
}
