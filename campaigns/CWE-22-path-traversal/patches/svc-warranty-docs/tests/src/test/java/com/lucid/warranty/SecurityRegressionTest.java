package com.lucid.warranty;

import java.nio.file.Files;
import java.nio.file.Path;

/** CWE-22: names from the request must not escape the attachment store. */
public class SecurityRegressionTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("att-root");
        Path base = Files.createDirectories(root.resolve("store"));
        Path secret = root.resolve("secret.txt");
        Files.writeString(secret, "db-password");
        AttachmentStore store = new AttachmentStore(base);
        for (String attack : new String[] {"../secret.txt", "claim/../../secret.txt", secret.toString()}) {
            boolean rejected;
            try { store.read(attack); rejected = false; } catch (IllegalArgumentException e) { rejected = true; }
            Check.that(rejected, "rejects " + attack);
        }
        Check.exit();
    }
}
