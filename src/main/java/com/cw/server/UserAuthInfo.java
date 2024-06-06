package com.cw.server;

import java.security.interfaces.ECPublicKey;

/**
 * @ClassName : UserAuthorization
 * @Description :   记录用户的授权信息
 * @Author : Ethan
 * @Date: 2023/5/26  14:34
 */
public class UserAuthInfo {
    private String userName;
    private String dataType;
    private String sign;
    private ECPublicKey userPubKey;
    private String priKeySharding;
    private String msg;

    public UserAuthInfo(String userName, String dataType, String sign, ECPublicKey userPubKey, String msg) {
        this.userName = userName;
        this.dataType = dataType;
        this.sign = sign;
        this.userPubKey = userPubKey;
        this.msg = msg;
    }

    public String getUserName() {
        return userName;
    }

    public String getDataType() {
        return dataType;
    }

    public String getSign() {
        return sign;
    }

    public ECPublicKey getUserPubKey() {
        return userPubKey;
    }

    public String getPriKeySharding() {
        return priKeySharding;
    }

    public void setPriKeySharding(String priKeySharding) {
        this.priKeySharding = priKeySharding;
    }

    public String getMsg() {
        return msg;
    }
}
