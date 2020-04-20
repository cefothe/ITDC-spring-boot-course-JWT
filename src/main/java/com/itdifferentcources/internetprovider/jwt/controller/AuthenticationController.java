package com.itdifferentcources.internetprovider.jwt.controller;

import com.itdifferentcources.internetprovider.jwt.services.AuthenticationService;
import com.itdifferentcources.internetprovider.jwt.services.dto.JwtResponseDTO;
import com.itdifferentcources.internetprovider.jwt.services.dto.LoginRequestDTO;
import com.itdifferentcources.internetprovider.jwt.services.dto.SignupRequestDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
@RestController
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/signup")
    public ResponseEntity<Void> signup(@RequestBody @Validated SignupRequestDTO createUserDto){
        authenticationService.signup(createUserDto);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @PostMapping("/signin")
    public JwtResponseDTO signin(@RequestBody @Validated LoginRequestDTO loginRequestDTO){
        return authenticationService.signin(loginRequestDTO);
    }

}
