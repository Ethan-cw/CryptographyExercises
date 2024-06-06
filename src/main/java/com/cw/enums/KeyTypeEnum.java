package com.cw.enums;


public enum KeyTypeEnum {
    PUB_KEY("n"), PRI_KEY_D0("d0"), PRI_KEY_D1("d1");

    private final String type;
    KeyTypeEnum(String type) {
        this.type = type;
    }

    public static KeyTypeEnum getByType(String type) {
        for (KeyTypeEnum keyType : KeyTypeEnum.values()) {
            if (keyType.getType().equals(type)){
                return keyType;
            }
        }
        return null;
    }

    public static boolean isPriKey(String keyType) {
        return keyType.equals(KeyTypeEnum.PRI_KEY_D0.getType()) || keyType.equals(KeyTypeEnum.PRI_KEY_D1.getType());
    }

    public static boolean isPubKey(String keyType) {
        return keyType.equals(KeyTypeEnum.PUB_KEY.getType());
    }

    public String getType() {
        return type;
    }
}
