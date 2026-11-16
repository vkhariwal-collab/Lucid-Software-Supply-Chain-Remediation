package com.lucid.warranty;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Serves warranty-claim attachments (photos, invoices) by name. */
public final class AttachmentStore {
    private final Path base;

    public AttachmentStore(Path base) {
        this.base = base;
    }

    public byte[] read(String name) throws IOException {
        Path root = base.toAbsolutePath().normalize();
        Path p = root.resolve(name).normalize();
        if (!p.startsWith(root)) {
            throw new IllegalArgumentException("attachment path escapes store");
        }
        return Files.readAllBytes(p);
    }
}
