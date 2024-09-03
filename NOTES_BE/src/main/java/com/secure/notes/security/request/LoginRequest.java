package com.secure.notes.security.request;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class LoginRequest { // editable DTO
    private String username;

    private String password;

}

