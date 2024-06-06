package com.cw.storage.reedsolomon;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;

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
public class SampleEncoder {
    public static final int DATA_SHARDS = 2; // 数据部分
    public static final int PARITY_SHARDS = 1; // 冗余部分
    public static final int TOTAL_SHARDS = 3; // 总共
    public static final int BYTES_IN_INT = 4; // 存储的数据是文件大小（四字节整数），后跟文件的内容，然后填充为四个字节的倍数和零。 填充是因为所有四个数据分片的大小必须相同。

    public static void main(String[] arguments) throws IOException {


        final File inputFile = new File("text.txt");
        if (!inputFile.exists()) {
            System.out.println("Cannot read input file: " + inputFile);
            return;
        }

//        String data = "hello hello!";


        // Get the size of the input file.  (Files bigger that
        // Integer.MAX_VALUE will fail here!)
        final int fileSize = (int) inputFile.length();
        System.out.println(inputFile);
        // Figure out how big each shard will be.  The total size stored
        // will be the file size (8 bytes) plus the file.
        final int storedSize = fileSize + BYTES_IN_INT;
        final int shardSize = (storedSize + DATA_SHARDS - 1) / DATA_SHARDS;

        // Create a buffer holding the file size, followed by
        // the contents of the file.
        final int bufferSize = shardSize * DATA_SHARDS;
        final byte[] allBytes = new byte[bufferSize];
        ByteBuffer.wrap(allBytes).putInt(fileSize);
        InputStream in = Files.newInputStream(inputFile.toPath());
        int bytesRead = in.read(allBytes, BYTES_IN_INT, fileSize);
        if (bytesRead != fileSize) {
            throw new IOException("not enough bytes read");
        }
        in.close();

        // Make the buffers to hold the shards.
        byte[][] shards = new byte[TOTAL_SHARDS][shardSize];

        // Fill in the data shards
        for (int i = 0; i < DATA_SHARDS; i++) {
            System.arraycopy(allBytes, i * shardSize, shards[i], 0, shardSize);
        }

        // Use Reed-Solomon to calculate the parity.
        ReedSolomon reedSolomon = ReedSolomon.create(DATA_SHARDS, PARITY_SHARDS);
        reedSolomon.encodeParity(shards, 0, shardSize);

        // Write out the resulting files.
        for (int i = 0; i < TOTAL_SHARDS; i++) {
            File outputFile = new File(
                    inputFile.getParentFile(),
                    inputFile.getName() + "." + i);
            OutputStream out = Files.newOutputStream(outputFile.toPath());
            out.write(shards[i]);
            out.close();
            System.out.println("wrote " + outputFile);
        }
    }
}
