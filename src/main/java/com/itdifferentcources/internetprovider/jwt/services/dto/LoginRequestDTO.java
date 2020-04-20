package com.itdifferentcources.internetprovider.jwt.services.dto;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Data
public class LoginRequestDTO {
    private String username;
    private String password;
}
