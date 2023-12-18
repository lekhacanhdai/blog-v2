package com.blog.authservice.config;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * @author dai.le-anh
 * @since 12/18/2023
 */

public class CustomAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication =
                (OAuth2TokenIntrospectionAuthenticationToken) authentication;
        tokenIntrospectionAuthentication.setDetails(Map.of("username", "admin", "password", "123456"));
        return tokenIntrospectionAuthentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2TokenIntrospectionAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
