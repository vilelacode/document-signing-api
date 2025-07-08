package com.vileladev.api.service.impl;

import com.vileladev.api.exception.DocumentSigningException;
import com.vileladev.api.service.SignatureSignerService;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class SignatureSignerServiceImpl implements SignatureSignerService {

    private static final Logger logger = LoggerFactory.getLogger(SignatureSignerServiceImpl.class);

    @Value("${app.signature.storage-dir}")
    private String storageDir;

    @Override
    public ResponseEntity<String> generateAttachedSignature(String pkcs12Path,
                                                            String pkcs12Password,
                                                            String alias,
                                                            String inputFilePath
    ) {
        try {

            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
                logger.info("BouncyCastle provider added on JCA");
            }

            // Verifica se já existe a pasta destino dos arquivos assinados
            Path dir = Paths.get(storageDir);
            if (!Files.exists(dir)) {
                Files.createDirectories(dir);
            }

            // Inicializa o KeyStore com o tipo PKCS12
            KeyStore keystore = KeyStore.getInstance("PKCS12");

            // Verifica se o caminho do arquivo PKCS#12 é válido
            try (InputStream ksStream = new FileInputStream(pkcs12Path)) {
                keystore.load(ksStream, pkcs12Password.toCharArray());
                logger.info("Keystore PKCS#12 loaded at: {}", pkcs12Path);
            }

            // Verifica se o alias existe no keystore e se é de uma chave privada
            Key key = keystore.getKey(alias, pkcs12Password.toCharArray());
            if (!(key instanceof PrivateKey)) {
                logger.error("This alias '{}' don't have a valid private key", alias);
                throw new IllegalArgumentException("This '" + alias + "' don't have any valid private key.");
            }
            PrivateKey privateKey = (PrivateKey) key;
            logger.info("Private key extracted by alias {}", alias);

            // Obtém a cadeia de certificados do keystore
            Certificate[] certificateChain = keystore.getCertificateChain(alias);
            if (certificateChain == null || certificateChain.length == 0) {
                throw new IllegalArgumentException("It was not possible to obtain the certificate for alias: " + alias);
            }

            // Converte para List<X509Certificate> para o JcaCertStore
            List<X509Certificate> certList = Stream.of(certificateChain)
                    .map(cert -> {
                        if (!(cert instanceof X509Certificate)) {
                            try {
                                throw new CertificateException("This entry is not X509Certificate");
                            } catch (CertificateException e) {
                                throw new RuntimeException(e);
                            }
                        }
                        return (X509Certificate) cert;
                    })
                    .collect(Collectors.toList());

            // Configura o ContentSigner com SHA-512 e RSA
            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA512withRSA");
            signerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);

            // Cria o objeto que efetivamente fará a assinatura
            ContentSigner contentSigner =
                    signerBuilder.build(privateKey);
            logger.info("ContentSigner created using SHA512withRSA");

            // Configura o SignerInfoGenerator para as informações do assinante e builda o digestProvider
            DigestCalculatorProvider digestProvider =
                    new JcaDigestCalculatorProviderBuilder()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build();
            SignerInfoGenerator signerInfoGen =
                    new JcaSignerInfoGeneratorBuilder(digestProvider)
                            .build(contentSigner, certList.get(0));
            logger.info("SignerInfoGenerator configured");

            // Configura o CMSSignedDataGenerator
            CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
            cmsGenerator.addSignerInfoGenerator(signerInfoGen);
            cmsGenerator.addCertificates(new JcaCertStore(certList));
            logger.info("CMSSignedDataGenerator with signer and certificates configured");

            // Lê o conteúdo do arquivo a ser assinado
            byte[] data = Files.readAllBytes(Paths.get(inputFilePath));
            CMSProcessableByteArray cmsData = new CMSProcessableByteArray(data);
            logger.info("Content by {} readed ({} bytes)", inputFilePath, data.length);

            // Gera o CMS SignedData
            CMSSignedData signedData = cmsGenerator.generate(cmsData, true);
            logger.info("SignedData CMS generated (attached)");

            // Cria o arquivo .p7s vazio na pasta de armazenamento configurada
            Path out = Files.createTempFile(Path.of(storageDir),"sig-", ".p7s");

            // Grava o resultado em disco de fato
            try (FileOutputStream fos = new FileOutputStream(out.toString())) {
                fos.write(signedData.getEncoded());
                logger.info("Signature CMS recorded at: {}", out);
            }

            // Lê o arquivo assinado e converte para Base64
            byte[] signatureBytes = Files.readAllBytes(out);
            String base64 = Base64.getEncoder().encodeToString(signatureBytes);

            return new ResponseEntity<>(base64, HttpStatus.OK);
        } catch (Exception ex) {
            Throwable root = (ex.getCause() != null) ? ex.getCause() : ex;
            throw new DocumentSigningException(
                    DocumentSigningException.resolveErrorCode(root),
                    " " + root.getMessage(),
                    root
            );
        }
    }
}
