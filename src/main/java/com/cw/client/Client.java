package com.cw.client;


import com.cw.client.enigma.EnigmaCoder;
import com.cw.enums.KeyTypeEnum;
import com.cw.enums.MsgTypeEnum;
import com.cw.utils.encryption.ECC;
import com.cw.utils.Utils;
import lombok.extern.slf4j.Slf4j;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.interfaces.ECPublicKey;
import java.util.*;


/**
 * @ClassName : Client
 * @Description : 用户系统
 * @Author : Ethan
 * @Date: 2023/5/24  10:40
 */
@Slf4j
public class Client {
    public enum ConsoleEnum {
        HELP, EXIT, JOIN, ENIGMA, DECRYPT, GEN, LIST, DELETE, GET, AUTH, QUERY, RECOVER
    }
    private final InetSocketAddress server;
    private final EnigmaCoder enigma =new EnigmaCoder(0,0,0);
    private final Scanner sc;
    private DatagramSocket udpSocket;
    private User host;
    private boolean isRunning;
    private UserMsgHandle handle;

    public Client(String name, int port, String serverIp) {
        sc = new Scanner(System.in);
        isRunning = true;
        server = new InetSocketAddress(serverIp, 9999);
        try {
            InetAddress localhost = InetAddress.getLocalHost();
            String localIP = localhost.getHostAddress();
            host = new User(name, localIP, port);
            log.info("Local IP: " + localIP);
            udpSocket = new DatagramSocket(port);
            // 将 ECPublicKey 对象转化为 Base64 编码的字符串
            String pubKeyStr = Base64.getEncoder().encodeToString(host.getPubKey().getEncoded());
            Utils.send(udpSocket, server, MsgTypeEnum.PUB + "@" + name + "@" + pubKeyStr);
            showHelp();
        } catch (Exception e) {
            System.out.println("[user]-getKeyPair:" + e.toString());
        }
    }

    private String getStrFromConsole() {
        return sc.nextLine();
    }

    private void showHelp() {
        System.out.println(
                "*************************************************************************************************************\n" +
                        "Instructions  \t Meanings                     \t formats             \t examples                         \n" +
                        "help:         \t Show help                    \n" +
                        "query:        \t Query on-chain data          \n" +
                        "exit:         \t Exit the system              \n" +
                        "delete:       \t Randomly delete a database   \n" +
                        "list:         \t List group friends           \t list@group          \t e.g., list@wangGroup             \n" +
                        "enigma:       \t Encrypt the key by enigma    \t enigma@key@status   \t e.g., enigma@xxxxyyyy@7 8 9      \n" +
                        "decrypt:      \t Decrypt the key by enigma    \t decrypt@num         \t e.g., decrypt@4842610267002466659\n" +
                        "join:         \t Join to group                \t join@groupName      \t e.g., join@wangGroup             \n" +
                        "gen:          \t Gen the group RSA key pair   \t gen@groupName       \t e.g., gen@wangGroup              \n" +
                        "get:          \t Get the RSA key (n/d)        \t gen@group@keyType   \t e.g., get@wangGroup@d            \n" +
                        "auth:         \t Authorize group signature    \t auth@group@msg      \t e.g., auth@wangGroup@hello       \n" +
                        "recover:      \t Recover group RSA key pair   \t recover@group       \t e.g., recover@wangGroup          \n" +
                        "*************************************************************************************************************");
    }

    public void run() {
        MsgHandelStart();
        while (isRunning) {
            String msg = getStrFromConsole();
            if (!Objects.equals(msg, "")) {
                consoleHandle(msg);
            }
        }
    }

    private void MsgHandelStart() {
        handle = new UserMsgHandle(host, udpSocket, enigma, server, 2048);
        Thread udpThread = new Thread(handle);
        udpThread.start();
    }

    private void consoleHandle(String msg) {
        String[] s = msg.split("@");
        String cmd = s[0].toUpperCase();
        if (!Utils.enumContains(ConsoleEnum.class, cmd)) {
            log.info("Unexpected command. Please refer to the following command.");
            showHelp();
            return;
        }
        ConsoleEnum consoleCommand = ConsoleEnum.valueOf(cmd);
        try {
            switch (consoleCommand) {
                case HELP: { // Show help menu
                    showHelp();
                    break;
                }
                case QUERY: { // Query on-chain data
                    Utils.send(udpSocket, server, MsgTypeEnum.QUERY + "@_" );
                    break;
                }
                case AUTH: { //auth@group@content
                    String group = s[1];
                    group = Utils.getSha256Str(group);
                    String content = s[2];
                    String authInfo = encryptAuthInfo(group, host.getServerPubKey(), content);
                    Utils.send(udpSocket, server, MsgTypeEnum.AUTH + "@" + host.getName() + "@" + authInfo);
                    break;
                }
                case GEN: { // gen@groupName   Generate RSA key pair
                    String group = s[1];
                    group = Utils.getSha256Str(group);
                    genGroupRsaKeyPair(group);
                    break;
                }
                case RECOVER: { // gen@groupName   Generate RSA key pair
                    String group = s[1];
                    group = Utils.getSha256Str(group);
                    recoverGroupRsaKeyPair(group);
                    break;
                }
                case GET: { // get@groupName@keyType  Obtain the RSA key
                    String group = s[1];
                    group = Utils.getSha256Str(group);
                    String keyType = s[2];
                    getKeyByType(group, keyType);
                    break;
                }
                case LIST: { // list@groupName   Show group friends
                    String group = s[1];
                    group = Utils.getSha256Str(group);
                    Utils.send(udpSocket, server, MsgTypeEnum.LIST + "@" + group + "@" + host.toJsonString());
                    break;
                }
                case ENIGMA: { // enigma@key@status  Encrypt the root key
                    String key = s[1];
                    String[] status = s[2].split(" ");
                    if (key.length() != 8 || status.length != 3) {
                        log.info("The enigma key you entered is incorrect, please re-enter it");
                    }
                    long[] longs = enigma.symmetricEncryptionCircuit(status, key);
                    host.setSignNum(longs);
                    log.info("The generated d1 and d2 are {} respectively.", Arrays.toString(longs));
                    break;
                }
                case JOIN: { // join@wangGroup  Join a specific group
                    String group = s[1];
                    group = Utils.getSha256Str(group);
                    if (host.getSignNum() == null) {
                        log.info("Please encrypt the key by enigma first.");
                    } else {
                        Utils.send(udpSocket, server, MsgTypeEnum.JOIN + "@" + group + "@" + host.toJsonString());
                    }
                    break;
                }
                case DECRYPT: { // decrypt@num  Decrypt root key
                    long l = Long.parseLong(s[1]);
                    enigma.recoverKeyByLong(l);
                    break;
                }
                case DELETE: { // delete  For convenience, the user clears one of the databases.
                    Utils.send(udpSocket, server, MsgTypeEnum.DELETE + "@_");
                    break;
                }
                case EXIT: {
                    System.exit(0);
                }
            }
        } catch (Exception e) {
            log.info("You entered the wrong instruction, please re-enter it");
        }

    }

    private void recoverGroupRsaKeyPair(String group) {
        log.info("Please re-enter key and status, then encrypt the key by enigma, for example xxxxyyyy@7 8 9");
        String msg = getStrFromConsole();
        String[] strings = msg.split("@");
        String key = strings[0];
        String[] status = strings[1].split(" ");
        long[] recoveredSigNum = enigma.symmetricEncryptionCircuit(status, key);
        host.setSignNum(recoveredSigNum);
        User friend = host.getFriend(group);
        InetSocketAddress friendAddress = friend.getAddress();

        // diffs [d1-r1, d2-r2]
        BigInteger[] diffs = host.getDiffs();
        Utils.send(udpSocket, friendAddress, MsgTypeEnum.RE_DIFF + "@" + group + "@" + Arrays.toString(diffs));
    }

    private void getKeyByType(String group, String keyType) {
        if (keyType.equals("d")) {
            keyType += host.getOrderByGroup(group);
        }
        if (KeyTypeEnum.getByType(keyType) == null) {
            log.info("The key type is incorrect, please re-enter it");
            return;
        }
        if (keyType.equals(KeyTypeEnum.PUB_KEY.getType())) {
            Utils.send(udpSocket, server, MsgTypeEnum.GET + "@" + host.getName() + "@" + group + "@" + keyType); // 取公钥不需要签名
        } else {
            Utils.send(udpSocket, server, MsgTypeEnum.GET + "@" + host.getName() + "@" + group + "@" + keyType + "@" + sign(group)); // 取私钥需要签名
        }
    }

    private void genGroupRsaKeyPair(String group) {
        if (host.getSignNum() == null) {
            log.info("Please encrypt the key by enigma first.");
            return;
        }
        if (!host.isOnline(group)) {
            log.info("Friends in the group are not online.");
            return;
        }
        User friend = host.getFriend(group);
        InetSocketAddress friendAddress = friend.getAddress();

        // diffs [d1-r1, d2-r2]
        BigInteger[] diffs = host.getDiffs();
        Utils.send(udpSocket, friendAddress, MsgTypeEnum.DIFF + "@" + group + "@" + Arrays.toString(diffs));
    }


    /**
     * @Description: 利用自己的ECC私钥 对 name + groupName 签名
     **/
    public String sign(String groupName) {
        return ECC.sign(host.getName() + groupName, host.getPriKey());
    }

    public String encryptAuthInfo(String group, ECPublicKey serverPubKey, String content) {
        String data = group + "@" + host.toJsonString() + "@" + sign(group) + "@" + content;
        String encrypt = "";
        try {
            encrypt = ECC.encrypt(data.getBytes(), serverPubKey);
        } catch (Exception e) {
            log.error("[ECC-encrypt]: {}", e.toString());
        }
        return encrypt;
    }

    public static void main(String[] args) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Please enter your login information and split it with @. ");
        System.out.println("For example wang@7777@127.0.0.1, where 7777 is the UDP port and 127.0.0.1 is server IP. ");
        String loginInformation = br.readLine();
        String[] s = loginInformation.split("@");
        String name = s[0];
        String port = s[1];
        String serverIp = s[2];
        Client client = new Client(name, Integer.parseInt(port), serverIp);
        client.run();
    }
}
