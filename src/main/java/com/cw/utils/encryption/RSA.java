package com.cw.utils.encryption;

import java.math.BigInteger;
import java.util.Random;


/**
* @ClassName : RSA
* @Description :  RSA 非对称加密，有生成秘钥对，加密和解密功能。
* @Author : Ethan
* @Date: 2023/5/26 10:39
*/
public class RSA {
    private final static int numLength = 1024;//素数长度
    private final static int accuracy = 100 ;//素数的准确率为1-(2^(-accuracy))

    //获取最大公约数
    private BigInteger getGCD(BigInteger a, BigInteger b) {
        if (b.byteValue() == 0) return a;
        return getGCD(b, a.mod(b));
    }

    //扩展欧几里得方法,计算 ax + by = 1中的x与y的整数解（a与b互质）
    private static BigInteger[] extGCD(BigInteger a, BigInteger b) {
        if (b.signum() == 0) {
            return new BigInteger[]{a, new BigInteger("1"), new BigInteger("0")};
        } else {
            BigInteger[] bigIntegers = extGCD(b, a.mod(b));
            BigInteger y = bigIntegers[1].subtract(a.divide(b).multiply(bigIntegers[2]));
            return new BigInteger[]{bigIntegers[0], bigIntegers[2], y};
        }
    }

    //超大整数超大次幂然后对超大的整数取模，利用蒙哥马利乘模算法,
    //(base ^ exp) mod n
    //依据(a * b) mod n=(a % n)*(b % n) mod n
    private static BigInteger expMode(BigInteger base, BigInteger exp, BigInteger mod) {
        BigInteger res = BigInteger.ONE;
        //拷贝一份防止修改原引用
        BigInteger tempBase = new BigInteger(base.toString());
        //从左到右实现简答
        /*
            D=1
            WHILE E>=0
        　　  IF E%2=0
        　　      C=C*C % N
        　　  E=E/2
        　　ELSE
        　　  D=D*C % N
        　　  E=E-1
        　　RETURN D
        */
        for (int i = 0; i < exp.bitLength(); i++) {
            if (exp.testBit(i)) {//判断对应二进制位是否为1
                res = (res.multiply(tempBase)).mod(mod);
            }
            tempBase = tempBase.multiply(tempBase).mod(mod);
        }
        return res;
    }

    //产生公钥与私钥
    public static SecretKey generateKey(BigInteger p, BigInteger q) {
        //令n = p * q。取 φ(n) = (p-1) * (q-1)。
        BigInteger n = p.multiply(q);
        //计算与n互质的整数个数 欧拉函数
        BigInteger fy = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        //取 e ∈ [1 < e < φ(n) ] ，( n , e )作为公钥对，这里取65537
        BigInteger e = new BigInteger("65537");
        //计算ed与fy的模反元素d。令 ed mod φ(n)  = 1，计算d，然后将( n , d ) 作为私钥对
        BigInteger[] bigIntegers = extGCD(e, fy);
        //计算出的x不能是负数，如果是负数，则进行x=x+fy。使x为正数，但是x<fy。
        BigInteger x = bigIntegers[1];
        if (x.signum() == -1) {
            x = x.add(fy);
        }
        //返回计算出的密钥
        return new SecretKey(n, e, x);
    }

    public static SecretKey generateKey() {
        BigInteger[] pq = getRandomPQ();
        return generateKey(pq[0], pq[1]);
    }

    public static SecretKey generateKeyByD1AndD2(BigInteger d1, BigInteger d2) {
        BigInteger[] pq = getNextPQ(d1, d2);
        return generateKey(pq[0], pq[1]);
    }

    // 签名 text^d mod n
    public static BigInteger sign(String text, SecretKey.PrivateKey privateKey) {
        BigInteger t = new BigInteger(text.getBytes());
        return expMode(t, privateKey.d, privateKey.n);
    }

    // 验证签名 s^e mod n == text mod n
    public static boolean verify(BigInteger sign, String text, SecretKey.PublicKey publicKey) {
        BigInteger t = new BigInteger(text.getBytes());
        BigInteger x1 = expMode(sign, publicKey.e, publicKey.n);
        BigInteger x2 = expMode(t, new BigInteger("1"), publicKey.n);
        return x1.equals(x2);
    }

    //加密 text^e mod n
    public static BigInteger encrypt(BigInteger text, SecretKey.PublicKey publicKey) {
        return expMode(text, publicKey.e, publicKey.n);
    }

    //解密 cipher^d mod n
    public static BigInteger decrypt(BigInteger cipher, SecretKey.PrivateKey privateKey) {
        return expMode(cipher, privateKey.d, privateKey.n);
    }

    //加密
    public static String encrypt(String text, SecretKey.PublicKey publicKey) {
        return encrypt(new BigInteger(text.getBytes()), publicKey).toString();
    }

    //解密
    public static String decrypt(String chipper, SecretKey.PrivateKey privateKey) {
        BigInteger bigInteger = expMode(new BigInteger(chipper), privateKey.d, privateKey.n);
        byte[] bytes = new byte[bigInteger.bitLength() / 8 + 1];
        for (int i = 0; i < bytes.length; i++) {
            for (int j = 0; j < 8; j++) {
                if (bigInteger.testBit(j + i * 8)) {
                    bytes[bytes.length - 1 - i] |= 1 << j;
                }
            }
        }
        return new String(bytes);
    }

    //产生比p和q大的1024位大质数
    public static BigInteger[] getNextPQ(BigInteger p, BigInteger q) {
        while (!p.isProbablePrime(accuracy)) {
            p = p.nextProbablePrime();
        }
        while (!q.isProbablePrime(accuracy)) {
            q = q.nextProbablePrime();
        }
        System.out.println(q);
        return new BigInteger[]{p, q};
    }

    //产生随机两个1024位的大质数
    public static BigInteger[] getRandomPQ() {
        BigInteger p, q;
        p = BigInteger.probablePrime(numLength, new Random());
        q = BigInteger.probablePrime(numLength, new Random());
        while (!p.isProbablePrime(accuracy)) {
            p = BigInteger.probablePrime(numLength, new Random());
        }
        while (!q.isProbablePrime(accuracy)) {
            p = BigInteger.probablePrime(numLength, new Random());
        }
        return new BigInteger[]{p, q};
    }


    //密匙对
    public static class SecretKey {
        BigInteger n, e, d;

        public SecretKey(BigInteger n, BigInteger e, BigInteger d) {
            this.n = n;
            this.e = e;
            this.d = d;
        }

        public PublicKey getPublicKey() {
            return new PublicKey(n, e);
        }

        public PrivateKey getPrivateKey() {
            return new PrivateKey(n, d);
        }

        //密钥
        public static class PrivateKey {
            public BigInteger n, d;

            public PrivateKey(BigInteger n, BigInteger d) {
                this.n = n;
                this.d = d;
            }

            @Override
            public String toString() {
                return "PrivateKey{" +
                        "n=" + n.toString(16) + '\n' +
                        ", d=" + d.toString(16) +
                        '}';
            }
        }

        //公钥
        public static class PublicKey {
            public BigInteger n, e;

            public PublicKey(BigInteger n, BigInteger e) {
                this.n = n;
                this.e = e;
            }

            @Override
            public String toString() {
                return "PublicKey{" +
                        "n=" + n.toString(16) + '\n' +
                        ", e=" + e.toString(16) +
                        '}';
            }
        }
    }


    public static void main(String[] args) {
        BigInteger n = new BigInteger("6e0fcce32d6f6cdf752f28232316ffea000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 16);
        BigInteger d = new BigInteger("3bf0c6f90289a8959a50705f9280b8274c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36e91333634ab56f90074938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6d", 16);

        RSA.SecretKey.PrivateKey privateKey = new RSA.SecretKey.PrivateKey(n, d);
        String msg = "hello";
        BigInteger sign = RSA.sign(msg, privateKey);
        RSA.SecretKey.PublicKey publicKey = new RSA.SecretKey.PublicKey(
                n, new BigInteger("65537"));
        boolean verified = RSA.verify(sign , msg, publicKey);
        System.out.println(verified);

        //明文内容不要超过1024位,超过后需要分段加密
//        String text = "Hello asdasdworld";
//        System.out.println(privateKey.getPublicKey().toString()); // PublicKey{n=2146738799500242751257286054641578062560640237400561580056893714227571892443243447813002829007288718904680361971057693926026743988407745131683064901767358185631428810107999068543106677196691813490242183551786365929912960057664165578440882018398363801258706453408158517985450215594192078250209171562379491902970740179494782905023120377618096819986167805170055319242151192125703364697936560354180186451994678090856116826683847225677790586961904851497676447413657916061618901475352106439044714718332731151725903366402259623424705898519372018453826045088552483381372710160106989634092266984399739191532902770726345014630110, e=65537}
//        System.out.println(privateKey.getPrivateKey().toString());// PrivateKey{n=226041161809059374530273881207827769103, d=64752685838584016614492501817552822273}


//        String chipper = RSA.encrypt(text, secretKey.getPublicKey());
//
//        System.out.println("加密后:\n" +
//                //密文长度可能会随着随机密钥的改变而改变，最长不超过2048位
//                "密文二进制长度:" + new BigInteger(chipper).bitLength()
//                + "\n"
//                + chipper);
//        String origin = RSA.decrypt(chipper, secretKey.getPrivateKey());
//        System.out.println("解密后:\n" + origin);
//
//        BigInteger sign = RSA.sign(text, secretKey.getPrivateKey());
//
//        System.out.println("签名后:\n" +
//                //密文长度可能会随着随机密钥的改变而改变，最长不超过2048位
//                "密文16进制长度:" + sign.toString(16).length()
//                + "\n"
//                + sign.toString(16));
//
//        boolean verified = RSA.verify(sign, text, secretKey.getPublicKey());
//        System.out.println("验证签名: " + verified);
//        String rawN = "6e0fcce32d6f6cdf752f28232316ffea000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
//        BigInteger bigInteger = new BigInteger(rawN, 16);
//
//        String rawD = "3bf0c6f90289a8959a50705f9280b8274c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36f4c90b36e91333634ab56f90074938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6c74938b6d";
//
//        BigInteger bigInteger2 = new BigInteger(rawD, 16);
//        System.out.println(n.equals(bigInteger));
//        System.out.println(d.equals(bigInteger2));
    }
}