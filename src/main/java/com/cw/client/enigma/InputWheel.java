package com.cw.client.enigma;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * @ClassName : InputWheel 输入轮
 * @Description :
 * 明文一位一位从密码机传到输入轮中，输入轮将明文对应的下标，最终在转子中变换的是替换表的下标，也就是整形数。
 * 输入轮中包含两个方法，一个是文字转为对应下标的整形数，另一个是下标转文字。
 * 输入轮不需要替换字母，秘钥子母∈(a~z，A~Z，0~9)
 * @Author : Ethan
 * @Date: 2023/5/15  10:31
 */

public class InputWheel {
    final static int CHAR_NUMBER = 26 * 2 + 10; // 26个大小写字母 + 0~9

    List<Character> link;

    public InputWheel() {
        // 添加大小写字母和数字
        Character[] all = new Character[62];
        for (int i = 0; i < 26; i++) {
            all[i] = (char) ('a' + i);
            all[i + 26] = (char) ('A' + i);
        }
        for (int i = 0; i < 10; i++) {
            all[i + 52] = (char) ('0' + i);
        }
        link = new ArrayList<Character>();
        Collections.addAll(link, all);
    }

    int char2Num(Character ch) {
        int num = -1;//默认为错误输出
        for (int i = 0; i < CHAR_NUMBER; i++) {
            if (ch.equals(link.get(i))) {
                num = i;
                break;
            }
        }
        return num;
    }

    Character num2Char(int num) {
        Character ch = '?'; //默认为错误输出
        ch = link.get(num % CHAR_NUMBER);
        return ch;
    }
}
