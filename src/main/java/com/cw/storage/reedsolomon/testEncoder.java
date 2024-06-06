package com.cw.storage.reedsolomon;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.HashMap;

/**
 * Command-line program encodes one file using Reed-Solomon 4+2.
 *
 * The one argument should be a file name, say "foo.txt".  This program
 * will create six files in the same directory, breaking the input file
 * into four data shards, and two parity shards.  The output files are
 * called "foo.txt.0", "foo.txt.1", ..., and "foo.txt.5".  Numbers 4
 * and 5 are the parity shards.
 *
 * The data stored is the file size (four byte int), followed by the
 * contents of the file, and then padded to a multiple of four bytes
 * with zeros.  The padding is because all four data shards must be
 * the same size.
 */
public class testEncoder {
    public static final int DATA_SHARDS = 2; // 数据部分
    public static final int PARITY_SHARDS = 1; // 冗余部分
    public static final int TOTAL_SHARDS = 3; // 总共
    public static final int BYTES_IN_INT = 4; // 存储的数据是文件大小（四字节整数），后跟文件的内容，然后填充为四个字节的倍数和零。 填充是因为所有四个数据分片的大小必须相同。


    public static void main(String[] arguments) throws IOException {

        HashMap<String, byte[][]> dataBase = new HashMap<>();

        String data = "hello hello!";
        // Get the size of the input file.  (Files bigger that
        // Integer.MAX_VALUE will fail here!)
        final int fileSize = data.length();
        // Figure out how big each shard will be.  The total size stored
        // will be the file size (8 bytes) plus the file.
        int storedSize = fileSize + BYTES_IN_INT;
        int shardSize = (storedSize + DATA_SHARDS - 1) / DATA_SHARDS;

        // Create a buffer holding the file size, followed by
        // the contents of the file.
        final int bufferSize = shardSize * DATA_SHARDS;

        ByteBuffer buffer=ByteBuffer.allocate(bufferSize);

        buffer.putInt(fileSize);
        buffer.put(data.getBytes());


        // Make the buffers to hold the shards.
        byte[][] shards = new byte[TOTAL_SHARDS][shardSize];

        // Fill in the data shards
        for (int i = 0; i < DATA_SHARDS; i++) {
            System.arraycopy(buffer.array(), i * shardSize, shards[i], 0, shardSize);
        }

        // Use Reed-Solomon to calculate the parity.
        ReedSolomon reedSolomon = ReedSolomon.create(DATA_SHARDS, PARITY_SHARDS);
        reedSolomon.encodeParity(shards, 0, shardSize);
        dataBase.put("AB", shards);
        buffer.clear();
    }
}
