package com.vileladev.api.service;

import org.springframework.http.ResponseEntity;

public interface SignatureSignerService {

    ResponseEntity<String> generateAttachedSignature(String pkcs12Path,
                                                     String pkcs12Password,
                                                     String alias,
                                                     String inputFilePath
    );
}
