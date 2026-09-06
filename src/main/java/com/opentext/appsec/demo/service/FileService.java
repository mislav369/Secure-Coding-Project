package com.opentext.appsec.demo.service;

import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.springframework.beans.factory.annotation.Value;
import java.nio.file.Path;

/**
 * File service with intentional security vulnerabilities.
 */
@Service
public class FileService {

    // Hardcoded path - security issue
    private final Path basePath;

    public FileService(
            @Value("${app.file.base-path}") String basePath) {
        this.basePath = Paths.get(basePath)
                .toAbsolutePath()
                .normalize();
    }

    /**
     * Read file with path traversal vulnerability.
     * Allows directory traversal attacks.
     */
    public String readFile(String filename) throws IOException {
        // Path Traversal vulnerability - no validation of filename
        File file = basePath.resolve(filename).toFile();
        return new String(Files.readAllBytes(file.toPath()));
    }

    /**
     * Write file with path traversal vulnerability.
     */
    public void writeFile(String filename, String content) throws IOException {
        // Path Traversal vulnerability
        File file = basePath.resolve(filename).toFile();
        Files.write(file.toPath(), content.getBytes());
    }

    /**
     * Execute system command with command injection vulnerability.
     * Extremely dangerous - allows arbitrary command execution.
     */
    public String executeCommand(String command) throws IOException {
        // Command Injection vulnerability - directly executing user input
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    /**
     * Execute command with shell - even more dangerous.
     */
    public String executeShellCommand(String userInput) throws IOException {
        // Command Injection via shell
        String command = "sh -c \"ls " + userInput + "\"";
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    /**
     * Read file with absolute path - path traversal vulnerability.
     */
    public String readAbsolutePath(String path) throws IOException {
        // Allows reading any file on the system
        return new String(Files.readAllBytes(Paths.get(path)));
    }

    /**
     * Delete file without validation.
     */
    public void deleteFile(String filename) throws IOException {
        File file = basePath.resolve(filename).toFile();
        Files.delete(file.toPath());
    }
}
