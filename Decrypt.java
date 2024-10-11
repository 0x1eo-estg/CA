import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Decrypt {
    
    // Constante que define o nome do ficheiro de entrada encriptado
    private static final String INPUT_FILE = "2024-CA-TP_C1_2_v01_Grupo07.enc"; 
    
    // Constante que define o nome do ficheiro de saída desencriptado
    private static final String OUTPUT_FILE = "2024-CA-TP_C1_2_v01_Grupo07.pdf"; 
    
    // Array de strings que define os algoritmos de desencriptação a serem utilizados
    private static final String[] ALGORITHMS = {"AES", "DES"}; 
    
    // Constante que define a chave secreta fornecida no enunciado
    private static final String KEY = "CA-2024-TP-2-LSIRC-ESTG!"; 

    public static void main(String[] args) {
        try {
            // Cria um objeto File para o ficheiro de entrada encriptado
            File inputFile = new File(INPUT_FILE);
            
            // Cria um objeto FileInputStream para ler o ficheiro de entrada
            FileInputStream fis = new FileInputStream(inputFile);
            
            // Cria um objeto FileOutputStream para escrever o ficheiro de saída
            FileOutputStream fos = new FileOutputStream(OUTPUT_FILE);

            // Cria um array de bytes para armazenar o conteúdo do ficheiro de entrada
            byte[] inputBytes = new byte[(int) inputFile.length()];
            
            // Lê o conteúdo do ficheiro de entrada e armazena no array de bytes
            fis.read(inputBytes);

            // Variáveis para armazenar a chave secreta, o objeto Cipher e os bytes desencriptados
            Key secretKey = null;
            Cipher cipher = null;
            byte[] decryptedBytes = null;

            // Loop que itera sobre os algoritmos de desencriptação
            for (String algorithm : ALGORITHMS) {
                try {
                    // Obtém a chave secreta para o algoritmo atual
                    secretKey = getSecretKey(algorithm);
                    
                    // Cria um objeto Cipher para o algoritmo atual
                    cipher = Cipher.getInstance(algorithm);
                    
                    // Inicializa o objeto Cipher para modo de desencriptação
                    cipher.init(Cipher.DECRYPT_MODE, secretKey);
                    
                    // Desencripta os bytes de entrada e armazena no array de bytes decryptedBytes
                    decryptedBytes = cipher.doFinal(inputBytes);

                    // Sai do loop caso a desencriptação seja bem sucedida
                    break;
                } catch (Exception e) {
                    // Se a desencriptação falhar, imprime uma mensagem de erro e continua para o próximo algoritmo
                    System.out.println("Desencriptação usando " + algorithm + " falhou");
                }
            }

            // Verifica se a desencriptação foi bem sucedida
            if (decryptedBytes!= null) {
                // Escreve os bytes desencriptados no ficheiro de saída
                fos.write(decryptedBytes);
                System.out.println("Ficheiro desencriptado com sucesso.");
            } else {
                System.out.println("Desencriptação falhada usando todos os algoritmos.");
            }

            // Fecha os streams de entrada e saída
            fis.close();
            fos.close();
        } catch (IOException e) {
            // Trata exceptions de entrada/saída
            e.printStackTrace();
        }
    }

    // Método que obtém a chave secreta para um algoritmo específico
    private static Key getSecretKey(String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        if (algorithm.equals("AES")) {
            // Cria uma chave secreta para o algoritmo AES
            return new SecretKeySpec(KEY.getBytes(), "AES");
        } else if (algorithm.equals("DES")) {
            // Cria uma chave secreta para o algoritmo DES
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            DESKeySpec desKeySpec = new DESKeySpec(KEY.getBytes());
            return keyFactory.generateSecret(desKeySpec);
        } else {
            // Lança uma exception se o algoritmo for inválido
            throw new IllegalArgumentException("Algoritmo de encriptação inválido");
        }
    }
}