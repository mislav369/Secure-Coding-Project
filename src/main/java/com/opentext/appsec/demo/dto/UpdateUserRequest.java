package com.opentext.appsec.demo.dto;

public record UpdateUserRequest(
        String email,
        String password
) {
}
