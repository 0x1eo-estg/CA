import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Calendar;

public class Signer {

    // Constants for keystore and PDF paths, and signature metadata
    private static final String KEYSTORE_PATH = "./7_8220302_Certificado.pfx";
    private static final String KEYSTORE_PASSWORD = "CA2024-Certificado";
    private static final String ALIAS = "Leandro_Afonso";
    private static final String PDF_PATH = "./2024-CA-TP_C30_v01.pdf";
    private static final String PDF_PATH_SIGNED = "./2024-CA-TP_C30_v01_signed.pdf";
    private static final String SIGNATURE_REASON = "Compreendo e aceito as regras do trabalho prático e eventuais alterações pontuais que sejam introduzidas.";
    private static final String SIGNATURE_LOCATION = "ESTG";

    public static void main(String[] args) {
        try {
            // Load the keystore and retrieve the private key and certificate
            KeyStore keystore = loadKeyStore(KEYSTORE_PATH, KEYSTORE_PASSWORD);
            PrivateKey privateKey = getPrivateKey(keystore, ALIAS, KEYSTORE_PASSWORD);
            Certificate certificate = keystore.getCertificate(ALIAS);

            // Load the PDF document
            try (PDDocument document = Loader.loadPDF(new File(PDF_PATH))) {
                // Sign the PDF
                signPDF(document, privateKey, PDF_PATH_SIGNED);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Method to load the keystore from a given path
    private static KeyStore loadKeyStore(String keystorePath, String password) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        try (InputStream inputStream = new FileInputStream(keystorePath)) {
            keystore.load(inputStream, password.toCharArray());
        }
        return keystore;
    }

    // Method to retrieve the private key from the keystore
    private static PrivateKey getPrivateKey(KeyStore keystore, String alias, String password) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        Key key = keystore.getKey(alias, password.toCharArray());
        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        } else {
            throw new KeyStoreException("The key is not a private key");
        }
    }

    // Method to sign the PDF document
    private static void signPDF(PDDocument document, PrivateKey privateKey, String outputPath) throws IOException {
        // Create a signature object
        PDSignature signature = createSignature();

        // Configure signature options
        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE);
        signatureOptions.setPage(document.getNumberOfPages() - 1);

        // Create a signature interface for signing the content
        SignatureInterface signatureInterface = createSignatureInterface(privateKey);
        document.addSignature(signature, signatureInterface, signatureOptions);

        // Save the signed document
        try (FileOutputStream output = new FileOutputStream(outputPath)) {
            document.saveIncremental(output);
        }
    }

    // Method to create and configure the signature object
    private static PDSignature createSignature() {
        PDSignature signature = new PDSignature();
        signature.setType(COSName.CERT);
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setLocation(SIGNATURE_LOCATION);
        signature.setReason(SIGNATURE_REASON);
        signature.setSignDate(Calendar.getInstance());
        return signature;
    }

    // Method to create a signature interface for signing the content
    private static SignatureInterface createSignatureInterface(PrivateKey privateKey) {
        return content -> {
            try {
                // Create a Signature object and initialize it with the private key
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(privateKey);
                byte[] buffer = new byte[8192];
                int length;
                // Read the content and update the signature
                while ((length = content.read(buffer)) != -1) {
                    signature.update(buffer, 0, length);
                }
                // Sign the content and return the result
                return signature.sign();
            } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                throw new IOException("Error occurred while signing the document.", e);
            }
        };
    }
}
