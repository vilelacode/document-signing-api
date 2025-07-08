package com.vileladev.api.service.impl;

import com.vileladev.api.exception.DocumentSigningException;
import com.vileladev.api.service.SignatureVerifierService;
import com.vileladev.api.service.record.Infos;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.*;
import java.text.ParseException;
import java.util.*;

@Service
public class SignatureVerifierServiceImpl implements SignatureVerifierService {

    Logger logger = LoggerFactory.getLogger(SignatureVerifierServiceImpl.class);

    @Override
    public ResponseEntity<Map<String, Infos>> verifyAttachedSignature(
            String signaturePath,
            String certificatesDir
    ) {

      try{
          // Check se o BouncyCastleProvider já está registrado
          if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
              Security.addProvider(new BouncyCastleProvider());
          }

          // Verifica se o caminho do arquivo de assinatura é válido
          CMSSignedData cms = null;
          try (InputStream sigStream = new FileInputStream(signaturePath)) {
              cms = new CMSSignedData(sigStream);
          }

          // Obtem as informações dos signatários pela CMSSignedData
          SignerInformationStore signers = cms.getSignerInfos();
          if (signers.size() == 0) {
              throw new IllegalArgumentException("Any signer information found in the CMS");
          }
          // Pegar o primeiro signatário
          SignerInformation signer = signers.getSigners().iterator().next();

          // Prepara o CertificateFactory para extrair certificados
          CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);

          // Verificar se o signatário possui certificado associado
          List<X509Certificate> certList = new ArrayList<>();
          for (Object obj : cms.getCertificates().getMatches(signer.getSID()).toArray()) {
              var x509certHolder = (X509CertificateHolder) obj;
              ByteArrayInputStream bais = new ByteArrayInputStream(x509certHolder.getEncoded());
              X509Certificate cert = (X509Certificate) cf.generateCertificate(bais);
              certList.add(cert);
          }
          if (certList.isEmpty()) {
              throw new IllegalArgumentException("No certificate found for the signer");
          }

          X509Certificate signerCert = certList.get(0);

          //Verificar integridade da assinatura
          boolean signatureValid = signer.verify(
                  new JcaSimpleSignerInfoVerifierBuilder()
                          .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                          .build(signerCert)
          );

          Set<TrustAnchor> trustAnchors = getTrustAnchorsByDirectory(certificatesDir, cf);

          // Validar o certificado do signatário pelas PKIX
          boolean result = certficateValidator(certList, cf, trustAnchors);

          // Logs da operação
          logger.info("=== Signer Certificate Information ===");
          logger.info("Subject DN: " + signerCert.getSubjectDN());
          logger.info("Issuer DN: " + signerCert.getIssuerDN());
          logger.info("Serial Number: " + signerCert.getSerialNumber());
          logger.info("Validate range: " + signerCert.getNotBefore() + " to " + signerCert.getNotAfter());
          logger.info("Digital signature valid and integrated " + signatureValid);

          return new ResponseEntity<>(
                    Map.of(
                            (result) ? "VALIDO" : "INVALIDO", new Infos(
                                    signerCert.getSubjectX500Principal().getName(),
                                    getSigningTimeBySigner(signer),
                                    Hex.toHexString(signerCert.getEncoded()),
                                    getHashAlgorithmNameFromOid(signer.getDigestAlgorithmID().getAlgorithm().getId())
                            )
                    ),
                    HttpStatus.OK
          );
      } catch (Exception ex) {
            Throwable root = (ex.getCause() != null) ? ex.getCause() : ex;
            throw new DocumentSigningException(
                    DocumentSigningException.resolveErrorCode(root),
                    " " + root.getMessage(),
                    root
            );
        }
    }

    // Carregar os TrustAnchors da API que estão em resources/cadeia/
    private static Set<TrustAnchor> getTrustAnchorsByDirectory(String certificatesDir, CertificateFactory cf) throws IOException {
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        java.nio.file.Files.list(java.nio.file.Paths.get(certificatesDir))
                .filter(p -> p.toString().toLowerCase().endsWith(".cer") || p.toString().toLowerCase().endsWith(".pem"))
                .forEach(p -> {
                    try (InputStream in = new FileInputStream(p.toFile())) {
                        X509Certificate caCert = (X509Certificate) cf.generateCertificate(in);
                        trustAnchors.add(new TrustAnchor(caCert, null));
                    } catch (Exception e) {
                        throw new RuntimeException("Erro ao carregar CA: " + p, e);
                    }
                });
        return trustAnchors;
    }

    // Valida o certificado do signatário usando a PKIX
    private boolean certficateValidator(List<X509Certificate> certList, CertificateFactory cf, Set<TrustAnchor> trustAnchors) throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        List<Certificate> certChain = new ArrayList<>(certList);
        CertPath certPath = cf.generateCertPath(certChain);
        PKIXParameters params = new PKIXParameters(trustAnchors);
        params.setRevocationEnabled(false);
        CertPathValidator validator = CertPathValidator.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
        try {
            validator.validate(certPath, params);
            return true;
        } catch (CertPathValidatorException e) {
            logger.info("Trust validation fail " + e.getMessage());
            return false;
        }
    }

    // Obtém o horário de assinatura do signatário
    private static Date getSigningTimeBySigner(SignerInformation signer) throws ParseException {
        Attribute signingTimeAtribute = signer.getSignedAttributes().get(CMSAttributes.signingTime);
        ASN1Encodable value = signingTimeAtribute.getAttrValues().getObjectAt(0);
        ASN1GeneralizedTime time = ASN1GeneralizedTime.getInstance(value);
        return time.getDate();
    }
    // Obtém o nome do algoritmo de hash a partir do OID
    private static String getHashAlgorithmNameFromOid(String oid) {
        return switch (oid) {
            case "1.3.14.3.2.26" -> "SHA-1";
            case "2.16.840.1.101.3.4.2.1" -> "SHA-256";
            case "2.16.840.1.101.3.4.2.2" -> "SHA-384";
            case "2.16.840.1.101.3.4.2.3" -> "SHA-512";
            case "2.16.840.1.101.3.4.2.4" -> "SHA-224";
            default -> "OID desconhecido: " + oid;
        };
    }
}
