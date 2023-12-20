package com.blog.authservice.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author dai.le-anh
 * @since 12/12/2023
 */

@RestController
public class TestController {
    @GetMapping("/hello")
    public String test(){
        return "Hello";
    }
}
