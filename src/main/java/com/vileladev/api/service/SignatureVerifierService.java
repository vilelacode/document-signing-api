package com.vileladev.api.service;

import com.vileladev.api.service.record.Infos;
import org.springframework.http.ResponseEntity;

import java.util.Map;

public interface SignatureVerifierService {

    ResponseEntity<Map<String, Infos>> verifyAttachedSignature(
            String signaturePath,
            String cadeiaDir
    );

}
