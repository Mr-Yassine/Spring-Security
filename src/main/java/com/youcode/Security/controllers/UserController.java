package com.youcode.Security.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class UserController {
    @RequestMapping({ "/api/user" })
    public String welcomePage() {
        return "Welcome!";
    }
}

