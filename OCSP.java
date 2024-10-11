import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

public class OCSP {

    private static final String KEYSTORE_TYPE = "Windows-MY";
    private static final String KEYSTORE_ALIAS = "<alias>"; // Replace with the alias of the certificate
    private static final String OCSP_URL = "http://ocsp.ecee.gov.pt/publico/ocsp"; // OCSP responder URL
    private static final String TSA_URL = "http://freetsa.org/tsr"; // Timestamp Authority URL
    private static final Logger LOGGER = Logger.getLogger(OCSP.class.getName());

    public static void main(String[] args) {
        try {
            // Load the keystore containing the certificate
            KeyStore keystore = loadKeystore();
            // Retrieve the certificate from the keystore using the alias
            X509Certificate certificate = getCertificateFromKeystore(keystore, KEYSTORE_ALIAS);
            // Log the expiry date of the certificate
            Date expiryDate = certificate.getNotAfter();
            LOGGER.info("Data de validade do certificado: " + expiryDate);

            // Create a CertificateID object for OCSP request
            CertificateID certificateID = getCertificateID(certificate);

            // Validate the certificate using OCSP
            if (validateCertificate(certificateID)) {
                // If the certificate is valid, calculate the hash
                byte[] hash = calculateHash(certificate);
                // Generate a timestamp request using the hash
                TimeStampRequest timeStampRequest = generateTimestampRequest(hash);
                // Get the timestamp response from the TSA
                TimeStampResp timeStampResp = getTimestampResponse(timeStampRequest);

                // Check the status of the timestamp response
                if (timeStampResp.getStatus().getStatus().intValue() == PKIStatus.GRANTED) {
                    // Save the timestamp request to a file
                    saveToFile("./file.tsq", timeStampRequest.getEncoded());
                    // Save the timestamp response to a file
                    saveToFile("./file.tsr", timeStampResp.getEncoded());
                    LOGGER.info("Timestamp aplicado com sucesso.");
                } else {
                    LOGGER.severe("Falha ao obter o timestamp: " + timeStampResp.getStatus().getStatusString());
                }
            } else {
                LOGGER.warning("O certificado não é válido de acordo com o serviço OCSP.");
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Erro ao processar OCSP/TSA", e);
        }
    }

    // Load the keystore
    private static KeyStore loadKeystore() throws Exception {
        KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE);
        keystore.load(null, null);
        return keystore;
    }

    // Retrieve the certificate from the keystore using the alias
    private static X509Certificate getCertificateFromKeystore(KeyStore keystore, String alias) throws Exception {
        return (X509Certificate) keystore.getCertificate(alias);
    }

    // Create a CertificateID object for OCSP request
    private static CertificateID getCertificateID(X509Certificate certificate) throws Exception {
        return new CertificateID(
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(certificate),
                certificate.getSerialNumber()
        );
    }

    // Validate the certificate using OCSP
    private static boolean validateCertificate(CertificateID certificateID) throws Exception {
        // Build the OCSP request
        OCSPReq ocspReq = buildOCSPRequest(certificateID);
        // Send the OCSP request and get the response
        OCSPResp ocspResponse = sendOCSPRequest(ocspReq);
        // Return true if the OCSP response status is successful
        return ocspResponse.getStatus() == OCSPResp.SUCCESSFUL;
    }

    // Build the OCSP request
    private static OCSPReq buildOCSPRequest(CertificateID certificateID) throws Exception {
        OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
        ocspReqBuilder.addRequest(certificateID);
        return ocspReqBuilder.build();
    }

    // Send the OCSP request and get the response
    private static OCSPResp sendOCSPRequest(OCSPReq ocspReq) throws Exception {
        URL url = new URL(OCSP_URL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/ocsp-request");
        connection.setRequestProperty("Accept", "application/ocsp-response");
        connection.setDoOutput(true);

        try (OutputStream os = connection.getOutputStream()) {
            os.write(ocspReq.getEncoded());
        }

        try (InputStream is = connection.getInputStream()) {
            return new OCSPResp(is);
        }
    }

    // Calculate the SHA-512 hash of the certificate
    private static byte[] calculateHash(X509Certificate certificate) throws Exception {
        byte[] encodedCert = certificate.getEncoded();
        return MessageDigest.getInstance("SHA-512").digest(encodedCert);
    }

    // Generate a timestamp request using the hash
    private static TimeStampRequest generateTimestampRequest(byte[] hash) throws Exception {
        TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
        timeStampRequestGenerator.setCertReq(true);
        return timeStampRequestGenerator.generate(TSPAlgorithms.SHA512, hash);
    }

    // Get the timestamp response from the TSA
    private static TimeStampResp getTimestampResponse(TimeStampRequest timeStampRequest) throws Exception {
        URL url = new URL(TSA_URL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/timestamp-query");
        connection.setRequestProperty("Accept", "application/timestamp-reply");
        connection.setDoOutput(true);

        try (OutputStream os = connection.getOutputStream()) {
            os.write(timeStampRequest.getEncoded());
        }

        try (InputStream is = connection.getInputStream();
             ASN1InputStream asn1InputStream = new ASN1InputStream(is)) {
            ASN1Sequence asn1Sequence = (ASN1Sequence) asn1InputStream.readObject();
            return TimeStampResp.getInstance(asn1Sequence);
        }
    }

    // Save data to a file
    private static void saveToFile(String path, byte[] data) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(new File(path))) {
            fos.write(data);
        }
    }
}
