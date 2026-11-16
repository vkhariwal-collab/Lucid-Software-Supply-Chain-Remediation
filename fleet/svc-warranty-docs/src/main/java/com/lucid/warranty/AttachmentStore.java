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
        Path p = base.resolve(name);
        return Files.readAllBytes(p);
    }
}
