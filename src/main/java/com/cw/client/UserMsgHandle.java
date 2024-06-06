package com.cw.client;

import com.cw.client.enigma.EnigmaCoder;
import com.cw.enums.MsgTypeEnum;
import com.cw.utils.Utils;
import lombok.extern.slf4j.Slf4j;

import javax.swing.*;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * @ClassName : UserMsgHandle
 * @Description :   处理用户消息的类
 * @Author : ethan
 * @Date: 2023/6/5  13:52
 */
@Slf4j
public class UserMsgHandle implements Runnable {
    private DatagramSocket udpSocket;
    private int byteNum;
    private boolean isRunning;
    private User host;
    private EnigmaCoder enigma;
    private InetSocketAddress server;

    public UserMsgHandle(User host, DatagramSocket udpSocket, EnigmaCoder enigma, InetSocketAddress server, int byteNum) {
        this.host = host;
        this.udpSocket = udpSocket;
        this.enigma = enigma;
        this.byteNum = byteNum;
        this.server = server;
        isRunning = true;
    }

    public void release() {
        isRunning = false;
        Utils.close(udpSocket);
    }

    @Override
    public void run() {
        while (isRunning) {
            try {
                byte[] container = new byte[byteNum];
                DatagramPacket packet = new DatagramPacket(container, 0, container.length);
                //3.阻塞式接受包裹
                udpSocket.receive(packet);
                //显示接受数据
                byte[] datas = packet.getData();
                String data = new String(datas).trim();
                if (!data.equals("")) {
                    udpHandle(data);
                }
            } catch (IOException e) {
                release();
            }
        }
    }

    private void udpHandle(String data) {
        String[] s = data.split("@");
        String msgType = s[0].toUpperCase();
        if (!Utils.enumContains(MsgTypeEnum.class, msgType)) {
            return;
        }
        switch (MsgTypeEnum.valueOf(msgType)) {
            case FRIEND: {
                String group = s[1];
                User groupFriend = User.fromJsonString(s[2]);
//                System.out.println(groupFriend);
                host.addFriend(group, groupFriend);
                break;
            }
            case ORDER: {
                String group = s[1];
                Integer order = Integer.valueOf(s[2]);
                host.putOrderByGroup(group, order);
                break;
            }
            case MSG: {
                String content = s[1];
                log.info(content);
                break;
            }
            case DIFF: {
                String group = s[1];
                User friend = host.getFriend(group);
                // diffs : [d1 - r1, d2 - r2]
                BigInteger[] otherDiffs = Utils.stringToBigIntegerArray(s[2]);
                obfuscation(group, friend, otherDiffs);
                break;
            }
            case RE_DIFF: {
                String group = s[1];
                User friend = host.getFriend(group);

                // diffs : [d1 - r1, d2 - r2]
                BigInteger[] otherDiffs = Utils.stringToBigIntegerArray(s[2]);
                reObfuscation(group, friend, otherDiffs);
                break;
            }
            case RS: {
                String group = s[1];
                BigInteger[] otherR128bits = Utils.stringToBigIntegerArray(s[2]);
                BigInteger[] rsSum = host.getRsSum(otherR128bits);
                Utils.send(udpSocket, server, MsgTypeEnum.SUM + "@" + group + "@" + Arrays.toString(rsSum));
                break;
            }
            case RE_RS:{
                String group = s[1];
                BigInteger[] otherR128bits = Utils.stringToBigIntegerArray(s[2]);
                BigInteger[] rsSum = host.getRsSum(otherR128bits);
                Utils.send(udpSocket, server, MsgTypeEnum.RE_SUM + "@" + group + "@" + Arrays.toString(rsSum));
                break;
            }
            case PUB: {
                String name = s[1];
                String content = s[2];
                byte[] serverPubKeyBytes = Base64.getDecoder().decode(content);
                try {
                    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(serverPubKeyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("EC");
                    ECPublicKey serverPubKey = (ECPublicKey) keyFactory.generatePublic(pubKeySpec);
                    String pubKeyStr = Base64.getEncoder().encodeToString(serverPubKey.getEncoded());
                    host.setServerPubKey(serverPubKey);
                    log.info("The public key {} of the {} has been obtained.", pubKeyStr, name);
                } catch (Exception e) {
                    log.error("PUB: " + e.toString());
                }
                break;
            }
        }
    }

    private void reObfuscation(String group, User friend, BigInteger[] otherDiffs) {
        // 在事件分派线程上创建和显示对话框
        SwingUtilities.invokeLater(() -> {
            JDialog dialog = new JDialog();
            dialog.setAlwaysOnTop(true);
            // 在单独的线程中创建和显示对话框，并让用户选择
            new Thread(() -> {

                JTextField textField = new JTextField();
                Object[] message = {
                        "Please re-enter key and enigma status:", textField
                };

                int option = JOptionPane.showConfirmDialog(null, message, host.getName() +":"+ friend.getName()+"'s request to recover RSA key pairs",
                        JOptionPane.YES_NO_OPTION);
                if (option == JOptionPane.OK_OPTION) {
                    String[] texts = textField.getText().split("@");
                    String key = texts[0];
                    String[] status = texts[1].split(" ");
                    long[] longs = enigma.symmetricEncryptionCircuit(status, key);
                    host.setSignNum(longs);

                    Utils.send(udpSocket, friend.getAddress(), MsgTypeEnum.MSG + "@" + host.getName() + " authorizes the recovery of RSA");

                    BigInteger[] diffsSum = host.getDiffsSum(otherDiffs);
                    Utils.send(udpSocket, friend.getAddress(), MsgTypeEnum.RE_RS + "@" + group + "@" + Arrays.toString(host.getRs()));
                    Utils.send(udpSocket, server, MsgTypeEnum.RE_SUM + "@" + group + "@" + Arrays.toString(diffsSum));
                } else {
                    Utils.send(udpSocket, friend.getAddress(), MsgTypeEnum.MSG + "@" + host.getName() + " does not agree to authorize the recovery of RSA");
                    log.info("Do not agree to authorize the recovery of RSA");
                }
            }).start();
        });
    }

    // 接收到 同组的 Diffs 和 产生 RSA秘钥对 请求， 同意则进行混淆加密，不同意则返回拒绝信息。
    private void obfuscation(String group, User friend, BigInteger[] otherDiffs) {
        // 在事件分派线程上创建和显示对话框
        SwingUtilities.invokeLater(() -> {
            JDialog dialog = new JDialog();
            dialog.setAlwaysOnTop(true);
            // 在单独的线程中创建和显示对话框，并让用户选择
            new Thread(() -> {
                int result = JOptionPane.showConfirmDialog(
                        dialog,
                        "Request to produce RSA key pairs",
                        host.getName() + ": " + friend.getName() + "'s request",
                        JOptionPane.YES_NO_OPTION
                );

                if (result == JOptionPane.YES_OPTION) {
                    Utils.send(udpSocket, friend.getAddress(), MsgTypeEnum.MSG + "@" + host.getName() + " authorizes the generation of RSA");
                    BigInteger[] diffsSum = host.getDiffsSum(otherDiffs);
                    Utils.send(udpSocket, friend.getAddress(), MsgTypeEnum.RS + "@" + group + "@" + Arrays.toString(host.getRs()));
                    Utils.send(udpSocket, server, MsgTypeEnum.SUM + "@" + group + "@" + Arrays.toString(diffsSum));
                } else {
                    Utils.send(udpSocket, friend.getAddress(), MsgTypeEnum.MSG + "@" + host.getName() + " does not agree to authorize the generation of RSA");
                    log.info("Do not agree to authorize the generation of RSA");
                }
            }).start();
        });
    }
}
