package com.itdifferentcources.internetprovider.jwt.services.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(code = HttpStatus.BAD_REQUEST)
public class UsernameAlreadyExist extends RuntimeException {

    public UsernameAlreadyExist(String message) {
        super(message);
    }
}
