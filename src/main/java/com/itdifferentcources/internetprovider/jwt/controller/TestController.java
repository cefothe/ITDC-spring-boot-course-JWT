package com.itdifferentcources.internetprovider.jwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/api/v1/test")
@RestController
public class TestController {

	@PreAuthorize("hasRole('CUSTOMER')")
    @GetMapping("")
    public String test(){
        return "HELLO";
    }
}
