package com.blog.authservice.domain.redisobject;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.util.SpringAuthorizationServerVersion;

import java.io.Serializable;
import java.sql.Timestamp;
import java.util.Map;
import java.util.Set;

/**
 * @author dai.le-anh
 * @since 12/21/2023
 */

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class CustomOAuth2Authorization implements Serializable {
    private String id;
    private String registeredClientId;
    private String principalName;
    private String authorizationGrantType;
    private Set<String> authorizedScopes;
    private String state;
    private Map<String, Object> attributes;
    private String authorizationCodeValue;
    private Timestamp authorizationCodeIssuedAt;
    private Timestamp authorizationCodeExpiredAt;
    private Map<String, Object> authorizationCodeMetadata;
    private String accessTokenValue;
    private Timestamp accessTokenIssuedAt;
    private Timestamp accessTokenExpiredAt;
    private String accessTokenType;
    private String accessTokenScopes;
    private Map<String, Object> accessTokenMetadata;
    private String oIDCIdTokenValue;
    private Timestamp oIDCIdTokenIssuedAt;
    private Timestamp oIDCIdTokenExpiredAt;
    private Map<String, Object> oIDCIdTokenMetadata;
    private String refreshTokenValue;
    private Timestamp refreshTokenIssuedAt;
    private Timestamp refreshTokenExpiredAt;
    private Map<String, Object> refreshTokenMetadata;
    private String userCodeValue;
    private Timestamp userCodeIssuedAt;
    private Timestamp userCodeExpiredAt;
    private Map<String, Object> userCodeMetadata;
    private String deviceCodeValue;
    private Timestamp deviceCodeIssuedAt;
    private Timestamp deviceCodeExpiredAt;
    private Map<String, Object> deviceCodeMetadata;

}
