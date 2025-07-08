package com.vileladev.api.controller;

import com.vileladev.api.service.SignatureSignerService;
import com.vileladev.api.service.impl.SignatureVerifierServiceImpl;
import com.vileladev.api.service.record.Infos;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;

import static com.vileladev.api.util.CmsPaths.*;

@RestController
@RequestMapping("/api")
public class SignatureRestController {

    private final SignatureSignerService signatureSignerService;
    private final SignatureVerifierServiceImpl signatureVerifierService;

    @Value("${alias}")
    private String ALIAS;

    @Value("${certificates.directory}")
    private String certificatesDir;


    public SignatureRestController(SignatureSignerService signatureSignerService,
                                   SignatureVerifierServiceImpl signatureVerifierService) {
        this.signatureSignerService = signatureSignerService;
        this.signatureVerifierService = signatureVerifierService;
    }

    @PostMapping(value = "/signature", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> signFile(
            @RequestPart("file") MultipartFile file,
            @RequestPart("pkcs12") MultipartFile pkcs12,
            @RequestPart("password") String password
    ) throws IOException {

        Path docPath = getDocPath(file);
        Path ksPath = getKsPath(pkcs12);

        return signatureSignerService.generateAttachedSignature(
                ksPath.toString(), password, ALIAS,
                docPath.toString()
        );
    }

    @PostMapping(value = "/verify", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, Infos>> verify(
            @RequestPart("signedFile") MultipartFile signedFile
    ) throws IOException {
        Path temp = getSignedFilePath(signedFile);

        return signatureVerifierService.verifyAttachedSignature(
                temp.toString(),certificatesDir
        );
    }
}
