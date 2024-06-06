package com.cw.client.enigma;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * @ClassName : Rotator  //类名
 * @Description :
 * 转子由一个代表接线的整形数组，当前转子的指针和转子的序号（外圈转子转一圈内圈转子转一个刻度），
 * 该密码机为三个转子，每个转子的接线和初始位置都可以单独设置。
 * 由于需要有设置当前转子指针的功能，所有有get和set指针的两个方法。还有通过替代表输入和输出的两个方法。
 * @Author : Ethan
 * @Date: 2023/5/15  10:22
 */

public class Rotator {
    final static int CHAR_NUMBER = 26 * 2 + 10; // 26个大小写字母 + 0~9
    private final List<Integer> link;
    private final List<Integer> rlink;
    private int count;
    private int point;
    private final int type;

    public Rotator(List<Integer> link, int point, int type) {
        this.link = link;
        Integer[] array = new Integer[CHAR_NUMBER];
        for (int i = 0; i < CHAR_NUMBER; i++) {
            array[i] = i;
        }
        rlink = new ArrayList<>();
        Collections.addAll(rlink, array);
        for (int i = 0; i < link.size(); i++) {
            rlink.set(link.get(i), i);
        }
        this.point = point;
        this.type = type;
        count = 0;
    }

    int getNum(int offset) {//所选数字为目前最低位的指针加上输入的偏移量
        count++;
        int sequence = offset + point;
        if (sequence >= CHAR_NUMBER) sequence = sequence % CHAR_NUMBER;
        // 先加 charnumber 使之变为正数，再取其余数
        return (link.get(sequence) - point + CHAR_NUMBER) % CHAR_NUMBER;
    }

    int getNumBack(int offset) {
        count++;
        int sequence = offset + point;
        if (sequence >= CHAR_NUMBER) sequence = sequence % CHAR_NUMBER;
        int num = (rlink.get(sequence) - point + CHAR_NUMBER) % CHAR_NUMBER;
        switch (type) {
            case 1: {//最低级转轮每次读取都转一次，字符进入后再出来共读取两次
                if (count % 2 == 0) {
                    point++;
                    point %= CHAR_NUMBER;
                    count = 0;
                }
                break;
            }
            case 2: {//最低轮转一圈第二轮转一刻
                if (count % CHAR_NUMBER == 0) {
                    point++;
                    point %= CHAR_NUMBER;
                    count = 0;
                }
                break;
            }
            case 3: {
                if (count % (CHAR_NUMBER * CHAR_NUMBER) == 0) {
                    point++;
                    point %= CHAR_NUMBER;
                    count = 0;
                }
                break;
            }
            default: {
                break;
            }
        }
        return num;
    }

    void setPoint(int point) {
        this.point = point;
        count = 0;
    }

    int getPoint() {
        return point;
    }
}
