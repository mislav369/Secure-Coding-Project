package com.opentext.appsec.demo.controller;

import com.opentext.appsec.demo.model.UserProfile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import java.util.UUID;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import java.io.FileInputStream;
import java.io.InvalidClassException;
import com.opentext.appsec.demo.security.WhitelistObjectInputStream;

@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/serialization")
public class SerializationController {

    private static final String STORAGE_DIR = "/tmp/serialized";

    @PostMapping("/save")
    public ResponseEntity<String> saveProfile(
            @RequestParam String username,
            @RequestParam String email,
            @RequestParam String role) {
        try {
            Files.createDirectories(Paths.get(STORAGE_DIR));
            String fileName = "profile-" + UUID.randomUUID() + ".ser";
            File file = new File(STORAGE_DIR, fileName);

            UserProfile profile = new UserProfile(username, email, role);
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(file))) {
                oos.writeObject(profile);
            }
            return ResponseEntity.ok("Serialized to " + file.getAbsolutePath());
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Serialization failed: " + e.getMessage());
        }
    }
    @PostMapping("/load")
    public ResponseEntity<String> loadProfile(@RequestParam String fileName) {
        if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\\")) {
            return ResponseEntity.badRequest().body("Invalid file name");
        }
        File file = new File(STORAGE_DIR, fileName);
        if (!file.exists()) {
            return ResponseEntity.status(404).body("File not found");
        }
        try {
            validateBinaryHeader(file);
            try (WhitelistObjectInputStream ois =
                         new WhitelistObjectInputStream(new FileInputStream(file))) {
                UserProfile profile = (UserProfile) ois.readObject();
                return ResponseEntity.ok("Deserialized OK: " + profile);
            }

        }  catch (Exception e) {
            return ResponseEntity.status(400).body("Deserialization failed: " + e.getMessage());
        }
    }
    private void validateBinaryHeader(File file) throws IOException {
        try (FileInputStream inputStream =
                     new FileInputStream(file)) {

            byte[] header = inputStream.readNBytes(4);

            if (header.length != 4
                    || header[0] != (byte) 0xAC
                    || header[1] != (byte) 0xED
                    || header[2] != (byte) 0x00
                    || header[3] != (byte) 0x05) {

                throw new SecurityException(
                        "Invalid Java serialization header");
            }
        }
    }

    @PostMapping("/save-bad")
    public ResponseEntity<String> saveBad() {
        try {
            Files.createDirectories(Paths.get(STORAGE_DIR));
            File file = new File(STORAGE_DIR, "bad.ser");
            java.util.HashMap<String, String> notAllowed = new java.util.HashMap<>();
            notAllowed.put("evil", "payload");
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(file))) {
                oos.writeObject(notAllowed);
            }
            return ResponseEntity.ok("Wrote non-whitelisted object to " + file.getAbsolutePath());
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Failed: " + e.getMessage());
        }
    }

    @PostMapping("/save-invalid")
    public ResponseEntity<String> saveInvalid() {
        try {
            Files.createDirectories(Paths.get(STORAGE_DIR));
            File file = new File(STORAGE_DIR, "invalid.ser");
            Files.writeString(file.toPath(), "this is not a serialized object");
            return ResponseEntity.ok("Wrote invalid (text) file to " + file.getAbsolutePath());
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Failed: " + e.getMessage());
        }
    }
}


