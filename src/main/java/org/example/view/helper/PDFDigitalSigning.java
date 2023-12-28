package org.example.view.helper;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import vn.edu.hcmuaf.fit.api.cer.CerDAO;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.List;

public class PDFDigitalSigning {

    public PDFDigitalSigning() {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
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

    public boolean verifyPdfSignedIntegrity(String billSignedPath) throws IOException, GeneralSecurityException {
        File file = new File(billSignedPath);
        boolean isCheck = false;
        try {
            InputStream resource = new FileInputStream(file);
            PdfDocument pdfDoc = new PdfDocument(new PdfReader(resource));
            SignatureUtil signUtil = new SignatureUtil(pdfDoc);
            List<String> names = signUtil.getSignatureNames();
            for (String name : names) {
                if (signUtil.signatureCoversWholeDocument(name)) {
                    PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);
                    isCheck = pkcs7.verifySignatureIntegrityAndAuthenticity();
                } else isCheck = false;
                System.out.println("===== " + name + " =====");
                System.out.println("Signature covers whole document: " + signUtil.signatureCoversWholeDocument(name));
                System.out.println("Document revision: " + signUtil.getRevision(name) + " of " + signUtil.getTotalRevisions());
                PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);
                System.out.println("Subject: " + CertificateInfo.getSubjectFields(pkcs7.getSigningCertificate()));
                System.out.println("Integrity check OK? " + pkcs7.verifySignatureIntegrityAndAuthenticity());
            }
            pdfDoc.close();
            resource.close();

        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            isCheck = false;
        }
        return isCheck;
    }

    public static void changePasswordKeyStoreFile(String keyStoreFilePath, String oldPassword, String newPassword) {
        String command = " keytool -storetype pkcs12 -keystore " + keyStoreFilePath + "  -storepasswd";

        try {
            Process process = Runtime.getRuntime().exec(command);

            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(process.getOutputStream()));
            writer.write(oldPassword);
            writer.write('\n');
            writer.write(newPassword);
            writer.write('\n');
            writer.write(newPassword);
            writer.flush();

            writer.close();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
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

    public boolean exportCertificate(String pathKeyStore, String pathDestCSR, String passKeyStore) {
        String command = "keytool -certreq -file " + pathDestCSR + " -alias shopphone -keystore " + pathKeyStore;
        System.out.println(command);

        try {
            Process process = Runtime.getRuntime().exec(command);

            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(process.getOutputStream()));
            writer.write(passKeyStore);
            writer.write('\n');
            writer.flush();

            writer.close();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) {
        CerDAO.getInstance().getCer(" and id = 19").ifPresent(cer -> {
            try {
                InputStream keystoreStream = cer.getData();
                InputStream inputStream = exportCertificate(keystoreStream, "123456");
                System.out.println(inputStream);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }


}
