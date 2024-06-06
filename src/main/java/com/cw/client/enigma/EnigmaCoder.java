package com.cw.client.enigma;

import com.cw.utils.Utils;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;

/**
 * @ClassName : EnigmaCoder
 * @Description : enigma 密码机 三个转轮和一个反射板构成
 * @Author : Administrator
 * @Date: 2023/5/15  10:10
 */

@Slf4j
public class EnigmaCoder {
    private final HashMap<Long, int[]> enigmaStatus; // 用来记录产生 d1 d2时候密码机的状态，以便于知道 d1 或者 d2 时候可以恢复 key

    public final static int CHAR_NUMBER = 26 * 2 + 10;
    private final InputWheel input;
    private final Rotator r1;
    private final Rotator r2;
    private final Rotator r3;
    private final Reflector ref;

    public EnigmaCoder(int num1, int num2, int num3) {
        Integer[] array = {19, 50, 6, 31, 53, 41, 54, 1, 56, 8,
                            7, 12, 44, 29, 32, 60, 57, 52, 55, 47,
                            30, 24, 16, 21, 3,17, 34, 40, 58, 33, 25,
                            4, 9, 22, 36, 2, 23, 43, 0, 37, 27, 15,
                            11, 35, 46, 10, 20, 49, 48, 13, 59, 26,
                            51, 18, 45, 39, 38, 14, 61, 28, 5, 42};
        ArrayList<Integer> list = new ArrayList<>();
        Collections.addAll(list, array);
        input = new InputWheel();
        r1 = new Rotator(list, num1, 1);
        r2 = new Rotator(list, num2, 2);
        r3 = new Rotator(list, num3, 3);
        ref = new Reflector();
        enigmaStatus = new HashMap<>();
    }

    public String encode(String str) {
        StringBuilder result = new StringBuilder();
        Character ch;
        int temp;
        for (int i = 0; i < str.length(); i++) {
            ch = str.charAt(i);
            temp = ref.getNum(r3.getNum(r2.getNum(r1.getNum(input.char2Num(ch)))));
            temp = r1.getNumBack(r2.getNumBack(r3.getNumBack(temp)));
            ch = input.num2Char(temp);
            result.append(ch);
        }
        return result.toString();
    }

    public void setCoder(int num1, int num2, int num3) {
        r1.setPoint(num1);
        r2.setPoint(num2);
        r3.setPoint(num3);
    }

    /**
     * @Description: 对称加密电路，输入8个字符和密码机状态（r1,r2,r3）, 生成用户的d1和d2，其中d1>d2
     */
    public long[] symmetricEncryptionCircuit(String[] status, String key) {
        int r1 = Integer.parseInt(status[0]) % EnigmaCoder.CHAR_NUMBER;
        int r2 = Integer.parseInt(status[1]) % EnigmaCoder.CHAR_NUMBER;
        int r3 = Integer.parseInt(status[2]) % EnigmaCoder.CHAR_NUMBER;
        setCoder(r1, r2, r3);
        long d1 = getEnigmaEncoder(key);
        long d2 = getEnigmaEncoder(key);
        if (d1 > d2) {
            return new long[]{d1, d2};
        } else {
            return new long[]{d2, d1};
        }
    }

    private long getEnigmaEncoder(String key) {
        int[] status = getStatus();
        long d = Utils.str2long(encode(key));
        enigmaStatus.put(d, status);
        return d;
    }

    /**
     * @Description: 通过 输入d1或者d2 来恢复用户的 Key
     **/
    public void recoverKeyByLong(long l) {
        if (!enigmaStatus.containsKey(l)) {
            log.info("Key does not exist.");
        }
        int[] status = enigmaStatus.get(l);
        setCoder(status[0], status[1], status[2]);
        String recoveredKey = encode(Utils.long2str(l));
        log.info("The recovered key is {}", recoveredKey);
    }

    public int[] getStatus(){
        return new int[] {r1.getPoint(), r2.getPoint(), r3.getPoint()};
    }
}
