package com.cw.client.enigma;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * @ClassName : Reflector
 * @Description :
 * 反射板只需要一个获得反射后下标的方法即可。
 * 需要注意的是反射板内部的link（替代表）和转子内部的不同，
 * 反射板的link需要正序的数组两两替换得到，转子则没有要求。
 * @Author : Administrator
 * @Date: 2023/5/15  10:24
 */
public class Reflector {
    final static int CHAR_NUMBER = 26 * 2 + 10; // 26个大小写字母 + 0~9

    private final List<Integer> link;

    public Reflector() {
        link = new ArrayList<Integer>(CHAR_NUMBER);
        for (int i = 0; i < CHAR_NUMBER; i+=2) {
            link.add(i+1);
            link.add(i);
        }
    }

    int getNum(int i) {
        return link.get(i);
    }
}

