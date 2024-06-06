package com.cw.utils;

import lombok.extern.slf4j.Slf4j;

import javax.xml.bind.DatatypeConverter;
import java.io.Closeable;
import java.io.IOException;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.nio.ByteBuffer;
import java.util.Enumeration;
import java.util.HashMap;

/**
 * @ClassName : Utils
 * @Description : 工具类
 * @Author : Administrator
 * @Date: 2023/5/15  18:58
 */

@Slf4j
public class Utils {

    public static void send(DatagramSocket udpSocket, InetSocketAddress toAddress, String msg) {
        try {
            byte[] datas = msg.getBytes();
            //2.创建数据包
            //参数：数据，数据开始点，数据长度，发送的地址
            DatagramPacket packet = new DatagramPacket(datas, 0, datas.length, toAddress);
            //3.发送数据包
            udpSocket.send(packet);
        } catch (IOException e) {
            log.error("Sending UDP messages error:", e);
        }
    }

    public static <T extends Enum<T>> boolean enumContains(Class<T> enumerator, String value) {
        for (T c : enumerator.getEnumConstants()) {
            if (c.name().equals(value)) {
                return true;
            }
        }
        return false;
    }

    public static String getIpAddress() {
        // Get the network interfaces of the current machine
        try {
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (networkInterfaces.hasMoreElements()) {
                NetworkInterface networkInterface = networkInterfaces.nextElement();
                Enumeration<InetAddress> inetAddresses = networkInterface.getInetAddresses();
                while (inetAddresses.hasMoreElements()) {
                    InetAddress inetAddress = inetAddresses.nextElement();
                    if (!inetAddress.isLinkLocalAddress() && !inetAddress.isLoopbackAddress()
                            && inetAddress instanceof java.net.Inet4Address
                            && inetAddress.getHostAddress().startsWith("192.")) {
                        return inetAddress.getHostAddress();
                    }
                }
            }
        }catch (Exception e){
            System.out.println(e.toString());
        }
        return "";
    }

    public static byte[] Random128bit() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        return bytes;
    }

    public static String bytesToHexString(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }

    public static long str2long(String str) {
        char[] chars = str.toCharArray();
        byte[] bytes = new byte[8];
        for (int i = 0; i < 8 && i < chars.length; i++) {
            bytes[i] = (byte) chars[i];
        }
        // 使用ByteBuffer将8个字节转换为long类型
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        return buffer.getLong();
    }

    public static BigInteger[] stringToBigIntegerArray(String str) {
        String[] stringArray = str
                .replace("[", "")
                .replace("]", "")
                .split(", ");
        BigInteger[] bigIntegerArray = new BigInteger[stringArray.length];
        for (int i = 0; i < stringArray.length; i++) {
            bigIntegerArray[i] = new BigInteger(stringArray[i]);
        }
        return bigIntegerArray;
    }

    public static String long2str(long value) {
        byte[] bytes = new byte[8];
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        buffer.putLong(value);
        char[] chars = new char[8];
        for (int i = 0; i < 8; i++) {
            chars[i] = (char) bytes[i];
        }
        return new String(chars);
    }

    public static String[] splitString(String str, int numOfChunks) {
        int length = str.length();
        int chunkSize = (int) Math.ceil((double) length / numOfChunks);
        String[] chunks = new String[numOfChunks];
        for (int i = 0; i < numOfChunks; i++) {
            int startIndex = i * chunkSize;
            int endIndex = Math.min(startIndex + chunkSize, length);
            chunks[i] = str.substring(startIndex, endIndex);
        }
        return chunks;
    }

    public static String combineStrings(String[] chunks) {
        StringBuilder sb = new StringBuilder();
        for (String chunk : chunks) {
            sb.append(chunk);
        }
        return sb.toString();
    }

    public static void close(Closeable... targets) {
        // Closeable是IO流中接口，"..."可变参数
        // IO流和Socket都实现了Closeable接口，可以直接用
        for (Closeable target : targets) {
            try {
                // 只要是释放资源就要加入空判断
                if (null != target) {
                    target.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * sha256加密
     *
     * @param str 要加密的字符串
     * @return 加密后的字符串
     */
    public static String getSha256Str(String str) {
        MessageDigest messageDigest;
        String encodeStr = "";
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(str.getBytes(StandardCharsets.UTF_8));
            encodeStr = byte2Hex(messageDigest.digest());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encodeStr;
    }

    /**
     * sha256加密 将byte转为16进制
     *
     * @param bytes 字节码
     * @return 加密后的字符串
     */
    private static String byte2Hex(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder();
        String temp;
        for (byte aByte : bytes) {
            temp = Integer.toHexString(aByte & 0xFF);
            if (temp.length() == 1) {
                //1得到一位的进行补0操作
                stringBuilder.append("0");
            }
            stringBuilder.append(temp);
        }
        return stringBuilder.toString();
    }

    public static void main(String[] args) {
        HashMap<String, Integer> map = new HashMap<>();
        int value = 123;
        String key = "int-value";
        map.put(key, value);
        System.out.println(map);

//        BigInteger bigNumber = new BigInteger("16621794896959495911");
//        System.out.println(Arrays.toString(splitString(bigNumber.toString(), 2)));


    }
}
