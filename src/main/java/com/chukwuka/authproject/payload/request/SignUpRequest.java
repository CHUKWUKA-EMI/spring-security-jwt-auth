package com.chukwuka.authproject.payload.request;

import com.sun.istack.NotNull;

import java.util.Set;

public class SignUpRequest {

    @NotNull
    private String username;

    @NotNull
    private String email;

    @NotNull
    private String password;

    private Set<String> role;

    public Set<String> getRole() {
        return role;
    }

    public void setRole(Set<String> role) {
        this.role = role;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
