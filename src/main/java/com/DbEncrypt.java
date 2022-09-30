package com;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;

public class DbEncrypt {

    public static int MacBitSize = 128;

    private static byte[] key;
    private static byte[] ivByte;

    public static void main(String[] args) {
        key = generateByteFromSecretKey("KEY");
        ivByte = generateByteFromSecretKey("IV");

        JFrame f = new JFrame("App");
        AppUIFrom appUIFrom = new AppUIFrom();


        appUIFrom.encryptButton.addActionListener(e -> {
            String cipherText = encrypt(appUIFrom.textField1.getText());
            appUIFrom.output1.setText(cipherText);
        });

        appUIFrom.decryptButton.addActionListener(e -> {
            String plaintext = decrypt(appUIFrom.cipherText.getText());
            appUIFrom.output2.setText(plaintext);
        });

        appUIFrom.genBlackList.addActionListener(e -> {
            String id = appUIFrom.blackListId.getText();
            String firstName = appUIFrom.blackListFirstName.getText();
            String lastName = appUIFrom.blackListLastName.getText();
            String key = id + firstName.toUpperCase() + lastName.toUpperCase();
            String uuid = UUID.nameUUIDFromBytes(key.getBytes()).toString();
            appUIFrom.blacklistOutput.setText("INSERT INTO irs.irs_watchlist (id, identity, firstname, lastname, country_name, created_date, updated_date) VALUES ('" + uuid + "', '" + id + "', '" + firstName + "', '" + lastName + "', 'MYANMAR', now(), now());");
        });

        appUIFrom.makeUuidButton.addActionListener(e -> {
            String senderId = appUIFrom.accumSenderId.getText();
            UUID uuid = UUID.nameUUIDFromBytes(senderId.toUpperCase().getBytes());
            appUIFrom.accumOutputText.setText(uuid.toString());
        });

        f.setContentPane(appUIFrom.mainPanel);
        f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        f.pack();
        f.setVisible(true);
    }

    private static byte[] generateByteFromSecretKey(String secretKey) {
        byte[] key = new byte[32];
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
            md.update(secretKey.getBytes(StandardCharsets.UTF_8));
            key = md.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return key;
    }

    public static String encrypt(String plainText) {
        if (plainText == null || "".equalsIgnoreCase(plainText))
            return "";

        String sR = "";
        try {
            byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);

            GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
            AEADParameters parameters =
                    new AEADParameters(new KeyParameter(key), MacBitSize, ivByte, null);

            cipher.init(true, parameters);

            byte[] encryptedBytes = new byte[cipher.getOutputSize(plainBytes.length)];
            int retLen = cipher.processBytes(plainBytes, 0, plainBytes.length, encryptedBytes, 0);
            cipher.doFinal(encryptedBytes, retLen);
            sR = Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return sR;
    }

    public static String decrypt(String encryptedText) {
        if (encryptedText == null || "".equalsIgnoreCase(encryptedText))
            return "";

        String sR = "";
        try {
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);

            GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
            AEADParameters parameters =
                    new AEADParameters(new KeyParameter(key), MacBitSize, ivByte, null);

            cipher.init(false, parameters);
            byte[] plainBytes = new byte[cipher.getOutputSize(encryptedBytes.length)];
            int retLen = cipher.processBytes
                    (encryptedBytes, 0, encryptedBytes.length, plainBytes, 0);
            cipher.doFinal(plainBytes, retLen);

            sR = new String(plainBytes, StandardCharsets.UTF_8);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return sR;
    }
}
