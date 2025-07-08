package com.vileladev.api.util;

import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class CmsPaths {

    private CmsPaths() {

    }

    public static Path getKsPath(MultipartFile pkcs12) throws IOException {
        Path ks = Files.createTempFile("ks-", ".p12");
        pkcs12.transferTo(ks);
        return ks;
    }

    public static Path getDocPath(MultipartFile file) throws IOException {
        Path in = Files.createTempFile("doc-", file.getOriginalFilename());
        file.transferTo(in);
        return in;
    }

    public static Path getSignedFilePath(MultipartFile signedFile) throws IOException {
        Path temp = Files.createTempFile("verify-", ".p7s");
        signedFile.transferTo(temp);
        return temp;
    }

}
