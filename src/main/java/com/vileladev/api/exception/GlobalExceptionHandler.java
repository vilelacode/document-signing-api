package com.vileladev.api.exception;

import com.vileladev.api.exception.record.ApiError;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.io.IOException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.LocalDateTime;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(DocumentSigningException.class)
    public ResponseEntity<ApiError> onDocumentError(DocumentSigningException ex,
                                                    HttpServletRequest req) {
        ApiError body = new ApiError(
                LocalDateTime.now(),
                HttpStatus.BAD_REQUEST.value(),
                "Document Signing Error",
                ex.getErrorCode(),
                ex.getMessage(),
                req.getRequestURI()
        );
        return ResponseEntity.badRequest().body(body);
    }

    @ExceptionHandler({UnrecoverableKeyException.class, CertificateException.class })
    public ResponseEntity<ApiError> onCryptoError(Exception ex, HttpServletRequest req) {
        ApiError body = new ApiError(
                LocalDateTime.now(),
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "Cryptographic Error",
                ex.getClass().getSimpleName(),
                ex.getMessage(),
                req.getRequestURI()
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }

    @ExceptionHandler(IOException.class)
    public ResponseEntity<ApiError> onIoError(IOException ex, HttpServletRequest req) {
        ApiError body = new ApiError(
                LocalDateTime.now(),
                HttpStatus.BAD_REQUEST.value(),
                "I/O Error",
                "IO_ERROR",
                ex.getMessage(),
                req.getRequestURI()
        );
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(body);
    }


    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> onAnyError(Exception ex, HttpServletRequest req) {
        ApiError body = new ApiError(
                LocalDateTime.now(),
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "Internal Server Error",
                "UNEXPECTED_ERROR",
                ex.getMessage(),
                req.getRequestURI()
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }
}