package com.opentext.appsec.demo.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SerializationControllerTest {

    private SerializationController controller;

    @BeforeEach
    void setUp() {
        controller = new SerializationController();
    }

    @Test
    void shouldSerializeAndDeserializeUserProfile() {
        ResponseEntity<String> saveResponse =
                controller.saveProfile(
                        "testuser",
                        "testuser@example.com",
                        "USER");

        assertEquals(
                200,
                saveResponse.getStatusCode().value());

        assertNotNull(saveResponse.getBody());

        String fullPath = saveResponse.getBody()
                .replace("Serialized to ", "");

        String fileName = Path.of(fullPath)
                .getFileName()
                .toString();

        ResponseEntity<String> loadResponse =
                controller.loadProfile(fileName);

        assertEquals(
                200,
                loadResponse.getStatusCode().value());

        assertTrue(
                loadResponse.getBody()
                        .contains("testuser"));
    }

    @Test
    void shouldRejectNonWhitelistedClass() {
        ResponseEntity<String> saveResponse =
                controller.saveBad();

        assertEquals(
                200,
                saveResponse.getStatusCode().value());

        ResponseEntity<String> loadResponse =
                controller.loadProfile("bad.ser");

        assertEquals(
                400,
                loadResponse.getStatusCode().value());

        assertTrue(
                loadResponse.getBody()
                        .contains("java.util.HashMap"));
    }

    @Test
    void shouldRejectInvalidBinaryFile() {
        ResponseEntity<String> saveResponse =
                controller.saveInvalid();

        assertEquals(
                200,
                saveResponse.getStatusCode().value());

        ResponseEntity<String> loadResponse =
                controller.loadProfile("invalid.ser");

        assertEquals(
                400,
                loadResponse.getStatusCode().value());

        assertTrue(
                loadResponse.getBody()
                        .contains(
                                "Invalid Java serialization header"));
    }

    @Test
    void shouldRejectInvalidFileName() {
        ResponseEntity<String> response =
                controller.loadProfile("../bad.ser");

        assertEquals(
                400,
                response.getStatusCode().value());

        assertEquals(
                "Invalid file name",
                response.getBody());
    }

    @Test
    void shouldReturn404ForMissingFile() {
        ResponseEntity<String> response =
                controller.loadProfile(
                        "file-that-does-not-exist.ser");

        assertEquals(
                404,
                response.getStatusCode().value());

        assertEquals(
                "File not found",
                response.getBody());
    }
}
