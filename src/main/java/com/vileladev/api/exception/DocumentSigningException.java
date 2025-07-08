package com.vileladev.api.exception;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class DocumentSigningException extends RuntimeException {
    private final String errorCode;

    public DocumentSigningException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public String getErrorCode() { return errorCode; }


    public static String resolveErrorCode(Throwable ex) {

        Throwable root = (ex.getCause() != null) ? ex.getCause() : ex;

        if (root instanceof FileNotFoundException) return "FILE_NOT_FOUND";
        if (root instanceof IOException) return "IO_ERROR";
        if (root instanceof UnrecoverableKeyException) return "KEY_RECOVERY_ERROR";
        if (root instanceof KeyStoreException) return "KEYSTORE_ERROR";
        if (root instanceof CertificateException) return "CERTIFICATE_ERROR";
        if (root instanceof OperatorCreationException) return "SIGNER_CREATION_ERROR";
        if (root instanceof CMSException) return "CMS_GENERATION_ERROR";
        if (root instanceof IllegalArgumentException) return "INVALID_ARGUMENT";

        return "UNEXPECTED_ERROR";

    }
}