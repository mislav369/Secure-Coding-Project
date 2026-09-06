package com.opentext.appsec.demo.dto;

public record CreateUserRequest(
        String username,
        String password,
        String email
) {
}
