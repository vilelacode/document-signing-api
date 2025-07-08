package com.vileladev.api.util;

import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

public class DigestUtil {

    private static final Logger logger = Logger.getLogger(String.valueOf(DigestUtil.class));

    public static String sha256FromResourceBC(String resourcePath) throws IOException {

        try (InputStream inputStream = DigestUtil.class.getResourceAsStream(resourcePath)) {
            if (inputStream == null) {
                throw new IOException("Document not found: " + resourcePath);
            }
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            try (DigestInputStream digestInputStream = new DigestInputStream(inputStream, md)) {
                byte[] buffer = new byte[4096];
                while (digestInputStream.read(buffer) != -1) {
                }
            }
            byte[] hash = md.digest();
            return Hex.toHexString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error initializing SHA-256 algorithm", e);
        }
    }

    public static void main(String[] args) throws Exception {
         logger.info("SHA-256:" + sha256FromResourceBC("/arquivos/doc.txt"));
    }
}
