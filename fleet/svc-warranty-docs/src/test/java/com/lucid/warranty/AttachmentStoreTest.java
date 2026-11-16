package com.lucid.warranty;

import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;

public class AttachmentStoreTest {
    public static void main(String[] args) throws Exception {
        Path base = Files.createTempDirectory("att");
        Files.createDirectories(base.resolve("claim-1001"));
        Files.writeString(base.resolve("claim-1001/photo.txt"), "front-bumper");
        AttachmentStore store = new AttachmentStore(base);
        Check.that(new String(store.read("claim-1001/photo.txt")).equals("front-bumper"), "reads nested attachment");
        boolean missing = false;
        try { store.read("claim-1001/none.txt"); } catch (NoSuchFileException e) { missing = true; }
        Check.that(missing, "missing attachment raises NoSuchFileException");
        Check.exit();
    }
}
