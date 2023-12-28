package org.example.view.helper;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.CertificateInfo;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.SignatureUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PDFChecker {


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
//                    boolean digitalSignCheck = checkDigitalSign(pkcs7, publicKey);
//                    System.out.println("Digital sign check OK? " + digitalSignCheck);
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

    private static boolean checkDigitalSign(PdfPKCS7 pkcs7, PublicKey publicKey) {
        try {
            X509Certificate signingCertificate = pkcs7.getSigningCertificate();
            signingCertificate.verify(publicKey);

//            signingCertificate.verify(signingCertificate.getPublicKey());
            return true;
        } catch (InvalidKeyException | SignatureException | NoSuchProviderException | NoSuchAlgorithmException |
                 CertificateException ex) {
            return false;
        }
    }
}
