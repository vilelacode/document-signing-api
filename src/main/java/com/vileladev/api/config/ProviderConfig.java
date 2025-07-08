package com.vileladev.api.config;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.Provider;
import java.security.Security;

@Configuration
public class ProviderConfig {

    @Bean
    public Provider bouncyCastleProvider() {
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        Security.insertProviderAt(bouncyCastleProvider, 1);
        return bouncyCastleProvider;
    }
}