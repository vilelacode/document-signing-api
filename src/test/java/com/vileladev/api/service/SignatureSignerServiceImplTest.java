package com.vileladev.api.service;

import com.vileladev.api.exception.DocumentSigningException;
import com.vileladev.api.service.impl.SignatureSignerServiceImpl;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

class SignatureSignerServiceImplTest {

    @InjectMocks
    private SignatureSignerServiceImpl signerService;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        signerService = new SignatureSignerServiceImpl();

        try {
            var storageDirField = SignatureSignerServiceImpl.class.getDeclaredField("storageDir");
            storageDirField.setAccessible(true);
            storageDirField.set(signerService, tempDir.toString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void testGenerateAttachedSignatureThrowsExceptionForInvalidPKCS12() throws Exception {

        Path fakePkcs12 = Files.createTempFile(tempDir, "fake", ".p12");
        Path fakeDoc = Files.createTempFile(tempDir, "doc", ".txt");
        String alias = "invalid";
        String password = "wrong";

        assertThrows(DocumentSigningException.class, () ->
            signerService.generateAttachedSignature(
                fakePkcs12.toString(),
                password,
                alias,
                fakeDoc.toString()
            )
        );
    }

    @Test
    void testGenerateAttachedSignatureSuccess() throws Exception {
        URL pkcs12Url = getClass().getClassLoader().getResource("pkcs12/certificado_teste_hub.pfx");
        assertNotNull(pkcs12Url, "PKCS12 not found at test classpath");

        URL docUrl = getClass().getClassLoader().getResource("arquivos/doc.txt");
        assertNotNull(docUrl, "This file isn't found at test classpath");

        Path pkcs12Path = Path.of(pkcs12Url.toURI());
        Path docPath = Path.of(docUrl.toURI());
        String alias = "{e2618a8b-20de-4dd2-b209-70912e3177f4}";
        String password = "bry123456";
        ResponseEntity<String> response = signerService.generateAttachedSignature(
            pkcs12Path.toString(),
            password,
            alias,
            docPath.toString()
        );

        assertEquals(200, response.getStatusCodeValue());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().isBlank());
    }

} 
