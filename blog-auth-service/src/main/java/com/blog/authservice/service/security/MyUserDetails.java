package com.blog.authservice.service.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.io.Serializable;
import java.util.Collection;

/**
 * @author dai.le-anh
 * @since 12/19/2023
 */

@Getter
@Setter
public class MyUserDetails extends User implements Serializable {
    private Long userId;
    private String email;
    private Boolean isActive;
    private String role;

    @Override
    public boolean isEnabled() {
        return isActive;
    }

    public MyUserDetails(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
    }
}
