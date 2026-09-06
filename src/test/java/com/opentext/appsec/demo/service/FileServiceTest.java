package com.opentext.appsec.demo.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileServiceTest {

    @TempDir
    Path temporaryDirectory;

    private FileService fileService;

    @BeforeEach
    void setUp() {
        fileService =
                new FileService(
                        temporaryDirectory.toString());
    }

    @Test
    void shouldWriteReadAndDeleteFile()
            throws IOException {

        fileService.writeFile(
                "test.txt",
                "secure content");

        Path file =
                temporaryDirectory.resolve("test.txt");

        assertTrue(Files.exists(file));

        assertEquals(
                "secure content",
                fileService.readFile("test.txt"));

        assertEquals(
                "secure content",
                fileService.readAbsolutePath(
                        file.toString()));

        fileService.deleteFile("test.txt");

        assertFalse(Files.exists(file));
    }
}
