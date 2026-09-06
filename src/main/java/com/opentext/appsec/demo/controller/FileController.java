package com.opentext.appsec.demo.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.opentext.appsec.demo.service.FileService;

import java.io.IOException;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;

import java.nio.file.NoSuchFileException;

/**
 * File controller with intentional security vulnerabilities.
 */
@RestController
@RequestMapping("/api/files")
public class FileController {

    private final FileService fileService;

    private static final String ERROR_PREFIX = "Error: ";

    public FileController(FileService fileService) {
        this.fileService = fileService;
    }

    /**
     * Read file with path traversal vulnerability.
     */
    @Operation(summary = "Read file (path traversal demo)", security = {@io.swagger.v3.oas.annotations.security.SecurityRequirement(name = "bearerAuth")})
    @GetMapping("/read")
    public ResponseEntity<String> readFile(@Parameter(description = "Filename to read (unsanitized)") @RequestParam String filename) {
        try {
            // Path Traversal vulnerability - allows reading any file
            String content = fileService.readFile(filename);
            return ResponseEntity.ok(content);
        } catch (IOException e) {
            // Information disclosure - exposing stack trace
            return ResponseEntity.status(500).body(ERROR_PREFIX + e.getMessage() + "\n" + java.util.Arrays.toString(e.getStackTrace()));
        }
    }

    /**
     * Write file with path traversal vulnerability.
     */
    @Operation(summary = "Write file (path traversal demo)", security = {@io.swagger.v3.oas.annotations.security.SecurityRequirement(name = "bearerAuth")})
    @PostMapping("/write")
    public ResponseEntity<String> writeFile(@Parameter(description = "Filename to write (unsanitized)") @RequestParam String filename, @RequestBody String content) {
        try {
            // Path Traversal vulnerability
            fileService.writeFile(filename, content);
            return ResponseEntity.ok("File written successfully: " + filename);
        } catch (IOException e) {
            return ResponseEntity.status(500).body(ERROR_PREFIX + e.getMessage());
        }
    }

    /**
     * Execute command with command injection vulnerability.
     */
    @Operation(summary = "Execute command (command injection demo)", security = {@io.swagger.v3.oas.annotations.security.SecurityRequirement(name = "bearerAuth")})
    @GetMapping("/exec")
    public ResponseEntity<String> executeCommand(@Parameter(description = "Command to execute (unsafe)") @RequestParam String cmd) {
        try {
            // Command Injection vulnerability - extremely dangerous
            String output = fileService.executeCommand(cmd);
            return ResponseEntity.ok(output);
        } catch (IOException e) {
            return ResponseEntity.status(500).body(ERROR_PREFIX + e.getMessage());
        }
    }

    /**
     * Execute shell command with command injection vulnerability.
     */
    @Operation(summary = "Execute shell command (command injection demo)", security = {@io.swagger.v3.oas.annotations.security.SecurityRequirement(name = "bearerAuth")})
    @GetMapping("/shell")
    public ResponseEntity<String> executeShellCommand(@Parameter(description = "Shell input (unsafe)") @RequestParam String input) {
        try {
            // Command Injection via shell
            String output = fileService.executeShellCommand(input);
            return ResponseEntity.ok(output);
        } catch (IOException e) {
            return ResponseEntity.status(500).body(ERROR_PREFIX + e.getMessage());
        }
    }

    /**
     * Read file with absolute path - path traversal vulnerability.
     */
    @Operation(summary = "Read absolute path (path traversal demo)", security = {@io.swagger.v3.oas.annotations.security.SecurityRequirement(name = "bearerAuth")})
    @GetMapping("/readabs")
    public ResponseEntity<String> readAbsolutePath(@Parameter(description = "Absolute path to read (unsafe)") @RequestParam String path) {
        try {
            // Allows reading any file on the system
            String content = fileService.readAbsolutePath(path);
            return ResponseEntity.ok(content);
        } catch (IOException e) {
            return ResponseEntity.status(500).body(ERROR_PREFIX + e.getMessage());
        }
    }

    /**
     * Delete file without validation.
     */
    @Operation(summary = "Delete file (path traversal demo)", security = {@io.swagger.v3.oas.annotations.security.SecurityRequirement(name = "bearerAuth")})
    @DeleteMapping("/delete")
    public ResponseEntity<String> deleteFile(
            @RequestParam String filename) {

        try {
            fileService.deleteFile(filename);
            return ResponseEntity.ok(
                    "File deleted: " + filename);
        } catch (NoSuchFileException exception) {
            return ResponseEntity.status(404).body(
                    "File not found: " + filename);
        } catch (IOException exception) {
            return ResponseEntity.status(500).body(
                    ERROR_PREFIX + exception.getMessage());
        }
    }
}
