package com.cw.server;

import com.cw.storage.StorageSystem;
import lombok.extern.slf4j.Slf4j;
import java.net.DatagramSocket;
import java.net.InetAddress;


/**
 * @ClassName : Server
 * @Description : Server 系统，
 * 整合 MPC、SignServer 和 StorageSystem，用 3个HashMap代表3个数据库
 * 以 group为单位管理用户，按 Sgn 分组进行混淆加密
 * 负责 group RSA 公私钥 的存，取和恢复, group 签名
 * 负责 保存用户 ECC 公钥，并验签
 * @Author : Ethan
 * @Date: 2023/5/24  15:48
 */
@Slf4j
public class Server {
    private static DatagramSocket udpSocket;
    private static ServerMsgHandle handle;
    private StorageSystem storage;
    private BlockchainSystem blockchainSystem;

    public Server(int port) {
        storage = new StorageSystem();
        blockchainSystem = new BlockchainSystem(storage);

        try {
            InetAddress addr = InetAddress.getLocalHost();
            udpSocket = new DatagramSocket(port);
            handle = new ServerMsgHandle(udpSocket, storage, blockchainSystem);
            Thread udpThread = new Thread(handle);
            udpThread.start();
            log.info("The server starts successfully at " + addr.getHostAddress() + ":" + port);
        } catch (Exception e) {
            log.error("Construct server errors:" + e);
            udpSocket.close();
        }
    }

    public static void main(String[] args) {
        Server s = new Server(9999);
    }
}
