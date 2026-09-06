package com.opentext.appsec.demo.controller;

import com.opentext.appsec.demo.service.FileService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import java.io.IOException;
import java.nio.file.NoSuchFileException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FileControllerTest {

    @Mock
    private FileService fileService;

    private FileController controller;

    @BeforeEach
    void setUp() {
        controller = new FileController(fileService);
    }

    @Test
    void shouldReadFileAndHandleError() throws IOException {
        when(fileService.readFile("test.txt"))
                .thenReturn("file content");

        ResponseEntity<String> success =
                controller.readFile("test.txt");

        assertEquals(200, success.getStatusCode().value());
        assertEquals("file content", success.getBody());

        when(fileService.readFile("error.txt"))
                .thenThrow(new IOException("read failed"));

        ResponseEntity<String> failure =
                controller.readFile("error.txt");

        assertEquals(500, failure.getStatusCode().value());
        assertTrue(failure.getBody().contains("read failed"));
    }

    @Test
    void shouldWriteFileAndHandleError() throws IOException {
        ResponseEntity<String> success =
                controller.writeFile(
                        "test.txt",
                        "content");

        assertEquals(200, success.getStatusCode().value());

        doThrow(new IOException("write failed"))
                .when(fileService)
                .writeFile("error.txt", "content");

        ResponseEntity<String> failure =
                controller.writeFile(
                        "error.txt",
                        "content");

        assertEquals(500, failure.getStatusCode().value());
        assertTrue(failure.getBody().contains("write failed"));
    }

    @Test
    void shouldExecuteCommandAndHandleError()
            throws IOException {

        when(fileService.executeCommand("test-command"))
                .thenReturn("command output");

        ResponseEntity<String> success =
                controller.executeCommand("test-command");

        assertEquals(200, success.getStatusCode().value());
        assertEquals("command output", success.getBody());

        when(fileService.executeCommand("bad-command"))
                .thenThrow(new IOException("command failed"));

        ResponseEntity<String> failure =
                controller.executeCommand("bad-command");

        assertEquals(500, failure.getStatusCode().value());
        assertTrue(failure.getBody().contains("command failed"));
    }

    @Test
    void shouldExecuteShellCommandAndHandleError()
            throws IOException {

        when(fileService.executeShellCommand("test"))
                .thenReturn("shell output");

        ResponseEntity<String> success =
                controller.executeShellCommand("test");

        assertEquals(200, success.getStatusCode().value());
        assertEquals("shell output", success.getBody());

        when(fileService.executeShellCommand("bad"))
                .thenThrow(new IOException("shell failed"));

        ResponseEntity<String> failure =
                controller.executeShellCommand("bad");

        assertEquals(500, failure.getStatusCode().value());
        assertTrue(failure.getBody().contains("shell failed"));
    }

    @Test
    void shouldReadAbsolutePathAndHandleError()
            throws IOException {

        when(fileService.readAbsolutePath("test-path"))
                .thenReturn("absolute content");

        ResponseEntity<String> success =
                controller.readAbsolutePath("test-path");

        assertEquals(200, success.getStatusCode().value());
        assertEquals("absolute content", success.getBody());

        when(fileService.readAbsolutePath("bad-path"))
                .thenThrow(new IOException("path failed"));

        ResponseEntity<String> failure =
                controller.readAbsolutePath("bad-path");

        assertEquals(500, failure.getStatusCode().value());
        assertTrue(failure.getBody().contains("path failed"));
    }

    @Test
    void shouldDeleteFileAndHandleErrors()
            throws IOException {

        ResponseEntity<String> success =
                controller.deleteFile("test.txt");

        assertEquals(200, success.getStatusCode().value());

        doThrow(new NoSuchFileException("missing.txt"))
                .when(fileService)
                .deleteFile("missing.txt");

        ResponseEntity<String> missing =
                controller.deleteFile("missing.txt");

        assertEquals(404, missing.getStatusCode().value());

        doThrow(new IOException("delete failed"))
                .when(fileService)
                .deleteFile("error.txt");

        ResponseEntity<String> failure =
                controller.deleteFile("error.txt");

        assertEquals(500, failure.getStatusCode().value());
        assertTrue(failure.getBody().contains("delete failed"));
    }
}
