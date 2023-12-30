package org.example.view.helper;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.layout.Document;
import com.itextpdf.signatures.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.*;

public class Cer {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    public static void createPdfFromInputStream(InputStream inputStream, String outputFilePath) {
        if (inputStream == null) {
            System.err.println("Input stream is null. Cannot create PDF.");
            return;
        }
        try (PdfReader pdfReader = new PdfReader(inputStream); PdfWriter pdfWriter = new PdfWriter(new FileOutputStream(outputFilePath)); PdfDocument pdfDocument = new PdfDocument(pdfReader, pdfWriter); Document document = new Document(pdfDocument)) {
            System.out.println("PDF file created successfully.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static PublicKey parsePublicKey(InputStream inputStream) throws Exception {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        try (DataInputStream dis = new DataInputStream(inputStream)) {
            byte[] keyBytes = new byte[dis.available()];
            dis.readFully(keyBytes);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", provider);

            return keyFactory.generatePublic(spec);
        }
    }


    public static InputStream signBill(InputStream billInputStream, InputStream keyStoreInputStream, String keyStorePassword) {
        try {
            BouncyCastleProvider provider = new BouncyCastleProvider();
            Security.addProvider(provider);

            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] keystorePassArr = keyStorePassword.toCharArray();
            ks.load(keyStoreInputStream, keystorePassArr);


            Enumeration<String> aliases = ks.aliases();

            String alias = aliases.nextElement();
            char[] privateKeyPassArr = keyStorePassword.toCharArray();
            PrivateKey pk = (PrivateKey) ks.getKey(alias, privateKeyPassArr);
            Certificate[] chain = ks.getCertificateChain(alias);

            if (chain == null || chain.length == 0) {
                throw new IllegalArgumentException("Certificate chain is empty or null.");
            }

            IExternalDigest digest = new BouncyCastleDigest();
            if (billInputStream.markSupported()) {
                billInputStream.reset();
            } else {
                // If mark is not supported, create a new ByteArrayInputStream
                byte[] billBytes = billInputStream.readAllBytes();
                billInputStream = new ByteArrayInputStream(billBytes);
            }
            PdfReader reader = new PdfReader(billInputStream);
            ByteArrayOutputStream signedPdfStream = new ByteArrayOutputStream();
            PdfSigner signer = new PdfSigner(reader, signedPdfStream, new StampingProperties());

            // appearance
            createSignApperience(signer);

            IExternalSignature signature = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, provider.getName());
            signer.signDetached(digest, signature, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);

            reader.close();

            return new ByteArrayInputStream(signedPdfStream.toByteArray());
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(("Error when sign bill: " + e.getMessage()));
            return null;
        }
    }

    public static InputStream generateAndLoadKeyStore2(String password, String urFullname, String orgName, String orgUnit, String city, String state, String countryCode) {
        try {
            BouncyCastleProvider provider = new BouncyCastleProvider();
            Security.addProvider(provider);
            // Generate Key Pair
            KeyPair keyPair = generateKeyPair();
            // Create self-signed X.509 certificate
            X509Certificate[] cert = generateCertificate(keyPair, urFullname, orgUnit, orgName, city, state, countryCode);

            // Load keystore
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, password.toCharArray());

            // Set key entry in the keystore
            ks.setKeyEntry("shopphone", keyPair.getPrivate(), password.toCharArray(), cert);

            // Save keystore to ByteArrayOutputStream
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ks.store(baos, password.toCharArray());
            InputStream andLoadKeyStore = new ByteArrayInputStream(baos.toByteArray());

            return andLoadKeyStore;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    private static X509Certificate[] generateCertificate(KeyPair keyPair, String urFullname, String orgUnit, String orgName, String city, String state, String countryCode) throws GeneralSecurityException, IOException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        X500Principal dnName = new X500Principal("CN=" + urFullname + ", OU=" + orgUnit + ", O=" + orgName + ", L=" + city + ", ST=" + state + ", C=" + countryCode);
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setSubjectDN(dnName);
        certGen.setIssuerDN(dnName);
        certGen.setNotBefore(new Date(System.currentTimeMillis()));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L));
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm("SHA256withRSA");

        X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");
        return new X509Certificate[]{cert};
    }

    public static void saveInputStreamToFile(InputStream inputStream, String filePath) {
        try (OutputStream outputStream = new FileOutputStream(filePath)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }


    private static void createSignApperience(PdfSigner signer) {
        Rectangle rect = new Rectangle(36, 250, 200, 100);
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance.setReason("Bill").setLocation("HCM")
                // Specify if the appearance before field is signed will be used
                // as a background for the signed field. The "false" value is the default value.
                .setReuseAppearance(false).setPageRect(rect).setPageNumber(1);
        signer.setFieldName("sig");
    }

    public static Map<String, String> viewCertificateDetails(InputStream keystoreInputStream, String pass) {
        Map<String, String> certificateDetails = new HashMap<>();

        try {
            // Load the keystore from the InputStream
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(keystoreInputStream, pass.toCharArray());

            // Get the certificate
            Certificate certificate = ks.getCertificate("shopphone");

            // Check if it's an X.509 certificate
            if (certificate instanceof X509Certificate) {
                X509Certificate x509Certificate = (X509Certificate) certificate;

                // Add certificate details to the map
                certificateDetails.put("Subject DN", x509Certificate.getSubjectDN().toString());
                certificateDetails.put("Issuer DN", x509Certificate.getIssuerDN().toString());
                certificateDetails.put("Serial Number", x509Certificate.getSerialNumber().toString());
                certificateDetails.put("Not Before", x509Certificate.getNotBefore().toString());
                certificateDetails.put("Not After", x509Certificate.getNotAfter().toString());
                certificateDetails.put("Signature Algorithm", x509Certificate.getSigAlgName());
                certificateDetails.put("Version", String.valueOf(x509Certificate.getVersion()));
                certificateDetails.put("Public Key Algorithm", x509Certificate.getPublicKey().getAlgorithm());
                certificateDetails.put("Public Key Format", x509Certificate.getPublicKey().getFormat());
                certificateDetails.put("Public Key", x509Certificate.getPublicKey().toString());
                certificateDetails.put("Certificate Type", x509Certificate.getType());
                certificateDetails.put("Certificate Hash Code", String.valueOf(x509Certificate.hashCode()));
                certificateDetails.put("Certificate Extensions", Arrays.toString(x509Certificate.getExtensionValue(" ")));
                certificateDetails.put("Certificate Basic Constraints", String.valueOf(x509Certificate.getBasicConstraints()));
                certificateDetails.put("Certificate Key Usage", String.valueOf(x509Certificate.getKeyUsage()));
                certificateDetails.put("Certificate Extended Key Usage", String.valueOf(x509Certificate.getExtendedKeyUsage()));
                certificateDetails.put("Certificate Subject Alternative Names", String.valueOf(x509Certificate.getSubjectAlternativeNames()));
                certificateDetails.put("Certificate Subject Unique ID", String.valueOf(x509Certificate.getSubjectUniqueID()));
                certificateDetails.put("Certificate Issuer Unique ID", String.valueOf(x509Certificate.getIssuerUniqueID()));
                certificateDetails.put("Certificate Issuer DN", x509Certificate.getIssuerDN().toString());
                certificateDetails.put("Certificate TBSCertificate", x509Certificate.getTBSCertificate().toString());
                certificateDetails.put("Certificate Signature", x509Certificate.getSignature().toString());
                certificateDetails.put("Certificate Signature Algorithm", x509Certificate.getSigAlgName());
                certificateDetails.put("Certificate Signature Algorithm OID", x509Certificate.getSigAlgOID());
                certificateDetails.put("Certificate Signature Algorithm Parameters", x509Certificate.getSigAlgParams().toString());
                certificateDetails.put("Certificate Signature Value", x509Certificate.getSignature().toString());

                // Add more details as needed...

            } else {
                certificateDetails.put("Error", "The provided certificate is not an X.509 certificate.");
            }

        } catch (Exception e) {
            certificateDetails.put("Error", e.getMessage());
        }

        return certificateDetails;
    }


    public static boolean checkDigitalSignPDF(InputStream inputStream, String nameSign) {
        try {
            if (inputStream == null) {
                return false;
            }
            PdfDocument pdfDoc = new PdfDocument(new PdfReader(inputStream));
            SignatureUtil signUtil = new SignatureUtil(pdfDoc);
            List<String> names = signUtil.getSignatureNames();
            for (String name : names) {
                if (name.equals(nameSign)) {
                    PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);
                    boolean signatureIntegrityAndAuthenticity = pkcs7.verifySignatureIntegrityAndAuthenticity();
                    pdfDoc.close();
                    inputStream.close();
                    return signatureIntegrityAndAuthenticity;
                }
            }
            pdfDoc.close();
            inputStream.close();
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static Map<String, String> verifyPdfSignedIntegrity(InputStream resource) throws IOException, GeneralSecurityException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        PdfDocument pdfDoc = new PdfDocument(new PdfReader(resource));
        SignatureUtil signUtil = new SignatureUtil(pdfDoc);
        List<String> names = signUtil.getSignatureNames();
        Map<String, String> map = new HashMap<>();
        for (String name : names) {
            map.put("name", name);
            map.put("revision", signUtil.getRevision(name) + " of " + signUtil.getTotalRevisions());
            map.put("signatureCoversWholeDocument", signUtil.signatureCoversWholeDocument(name) + "");
            try {
                PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);
                X509Certificate signingCertificate = pkcs7.getSigningCertificate();
                CertificateInfo.X500Name subjectFields = CertificateInfo.getSubjectFields(pkcs7.getSigningCertificate());
                map.put("ST", subjectFields.getField("ST"));
                map.put("CN", subjectFields.getField("CN"));
                map.put("OU", subjectFields.getField("OU"));
                map.put("O", subjectFields.getField("O"));
                map.put("L", subjectFields.getField("L"));
                map.put("C", subjectFields.getField("C"));
                map.put("signatureIntegrityAndAuthenticity", pkcs7.verifySignatureIntegrityAndAuthenticity() + "");
                map.put("seri", signingCertificate.getSerialNumber() + "");
                map.put("before", signingCertificate.getNotBefore() + "");
                map.put("after", signingCertificate.getNotAfter() + "");
                map.put("algorithm", signingCertificate.getSigAlgName() + "");
                map.put("version", signingCertificate.getVersion() + "");
                map.put("subjectDN", signingCertificate.getSubjectDN() + "");
                map.put("issuerDN", signingCertificate.getIssuerDN() + "");
                map.put("location", pkcs7.getLocation());
                map.put("reason", pkcs7.getReason());
                Calendar timeStampDate = pkcs7.getTimeStampDate();
                if (timeStampDate != null) {
                    map.put("timeStampDate", timeStampDate + "");
                }
                TimeStampToken timeStampToken = pkcs7.getTimeStampToken();
                if (timeStampToken != null) {
                    map.put("timeStampToken", timeStampToken.getTimeStampInfo().getTsa() + "");
                } else {
                    map.put("timeStampToken", pkcs7.verifyTimestampImprint() + "");
                }
                map.put("signDate", pkcs7.getSignDate().get(Calendar.YEAR) + "-" +
                        (pkcs7.getSignDate().get(Calendar.MONTH) + 1) + "-" +
                        pkcs7.getSignDate().get(Calendar.DAY_OF_MONTH) + " " +
                        pkcs7.getSignDate().get(Calendar.HOUR_OF_DAY) + ":" +
                        pkcs7.getSignDate().get(Calendar.MINUTE) + ":" +
                        pkcs7.getSignDate().get(Calendar.SECOND));

                map.put("subjectAlternativeNames", signingCertificate.getSubjectAlternativeNames() + "");
            } catch (InvalidKeyException e) {
                System.out.println("Error reading signature data for " + name + ": Invalid Key - " + e.getMessage());
            } catch (Exception e) {
                System.out.println("Error reading signature data for " + name + ": " + e.getMessage());
            }
        }
        pdfDoc.close();
        resource.close();
        return map;
    }

    public InputStream sign(InputStream billPath, String keyStorePassword, InputStream keyStoreData) {
        try {
            BouncyCastleProvider provider = new BouncyCastleProvider();
            Security.addProvider(provider);

            KeyStore ks = KeyStore.getInstance("pkcs12");
            char[] keystorePassArr = keyStorePassword.toCharArray();
            ks.load(keyStoreData, keystorePassArr);

            String alias = null;
            Enumeration<String> aliases = ks.aliases();
            if (aliases.hasMoreElements()) {
                alias = aliases.nextElement();
            } else {
                return null;
            }

            char[] privateKeyPassArr = keyStorePassword.toCharArray();
            PrivateKey pk = (PrivateKey) ks.getKey(alias, privateKeyPassArr);
            Certificate[] chain = ks.getCertificateChain(alias);

            IExternalDigest digest = new BouncyCastleDigest();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            PdfReader reader = new PdfReader(billPath);
            PdfSigner signer = new PdfSigner(reader, outputStream, new StampingProperties());
            Rectangle rect = new Rectangle(36, 250, 200, 100);
            PdfSignatureAppearance appearance = signer.getSignatureAppearance();
            appearance.setReason("Bill Digital Signature").setLocation("Hochiminh City").setReuseAppearance(false).setPageRect(rect).setPageNumber(1);
            signer.setFieldName("shopphone");
            IExternalSignature signature = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, provider.getName());
            signer.signDetached(digest, signature, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);


            // Return the signed document as an InputStream
            return new ByteArrayInputStream(outputStream.toByteArray());

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    public static InputStream changePasswordKeyStore(InputStream keystoreInputStream, String oldPassword, String newPassword) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            // Load the keystore
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(keystoreInputStream, oldPassword.toCharArray());

            // Get the private key
            String alias = keystore.aliases().nextElement();
            PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, oldPassword.toCharArray());

            // Convert private key to PEM format
            StringWriter privateKeyWriter = new StringWriter();
            try (JcaPEMWriter pemWriter = new JcaPEMWriter(privateKeyWriter)) {
                pemWriter.writeObject(privateKey);
            }

            // Parse the PEM private key
            PEMParser pemParser = new PEMParser(new StringReader(privateKeyWriter.toString()));
            Object pemObject = pemParser.readObject();
            pemParser.close();

            if (!(pemObject instanceof PEMKeyPair)) {
                throw new RuntimeException("Invalid PEM private key format");
            }

            PEMKeyPair pemKeyPair = (PEMKeyPair) pemObject;

            // Decrypt the PEM private key with the new password
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            PrivateKey decryptedPrivateKey = converter.getPrivateKey(pemKeyPair.getPrivateKeyInfo());

            // Update the keystore with the new password
            KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(newPassword.toCharArray());
            KeyStore.Entry entry = new KeyStore.PrivateKeyEntry(decryptedPrivateKey, new Certificate[]{keystore.getCertificate(alias)});
            keystore.setEntry(alias, entry, entryPassword);

            // Convert the updated keystore to InputStream
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            keystore.store(outputStream, newPassword.toCharArray());
            InputStream updatedKeystoreInputStream = new ByteArrayInputStream(outputStream.toByteArray());

            System.out.println("Keystore password changed successfully.");
            return updatedKeystoreInputStream;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static InputStream exportCertificate(InputStream keystoreStream, String password) {
        try {
            // Load keystore
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(keystoreStream, password.toCharArray());

            // Get the certificate
            Certificate cert = ks.getCertificate("shopphone");

            // Convert certificate to InputStream
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(cert);
            oos.close();

            return new ByteArrayInputStream(baos.toByteArray());

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

}
