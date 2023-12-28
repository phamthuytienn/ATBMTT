package org.example.view.helper;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.layout.Document;
import com.itextpdf.signatures.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import vn.edu.hcmuaf.fit.api.cer.CerDAO;
import vn.edu.hcmuaf.fit.api.users.User;

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
            // Perform operations on the Document here if needed
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


    public static void generateAndLoadKeyStore2(User acc, String password, String urFullname, String orgName, String orgUnit, String city, String state, String countryCode) {
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

            saveCertificateToDatabase(acc, andLoadKeyStore);

        } catch (Exception e) {
            e.printStackTrace();
        }
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

    public static void main(String[] args) {
        CerDAO.getInstance().getCer(" and id  =20").ifPresent(cer -> {
            try {
                System.out.println(viewCertificateDetails(cer.getData(), "123123"));
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    private static void saveCertificateToDatabase(User acc, InputStream byteArr) {
        vn.edu.hcmuaf.fit.api.cer.Certificate myCertificate = new vn.edu.hcmuaf.fit.api.cer.Certificate();
        myCertificate.setUserId(acc.getId());
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        myCertificate.setStartDate(timestamp);
        myCertificate.setData(byteArr);
        myCertificate.setCreated_at(timestamp);
        myCertificate.setUpdated_at(timestamp);
        myCertificate.setEndDate(new Timestamp(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L));
        myCertificate.setStatus(vn.edu.hcmuaf.fit.constant.Certificate.SELECTED.getQuery());
        CerDAO.getInstance().update(" update certificates set status = 'EXPIRED' where userId = " + acc.getId(), null);
        CerDAO.getInstance().create(myCertificate);
    }


}
