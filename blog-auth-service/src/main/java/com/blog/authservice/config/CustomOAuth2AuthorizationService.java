package com.blog.authservice.config;

import com.blog.authservice.domain.redisobject.TokenKey;
import com.blog.authservice.domain.repository.redis.TokenRedisRepository;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.util.Assert;

/**
 * @author dai.le-anh
 * @since 12/21/2023
 */

public final class CustomOAuth2AuthorizationService implements OAuth2AuthorizationService {
    private final TokenRedisRepository tokenRedisRepository;

    public CustomOAuth2AuthorizationService(TokenRedisRepository tokenRedisRepository) {
        this.tokenRedisRepository = tokenRedisRepository;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        TokenKey key = new TokenKey();
        key.setAuth(authorization);
        tokenRedisRepository.save(key);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        var key = tokenRedisRepository.findById(authorization.getId());
        key.ifPresent(tokenRedisRepository::delete);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        var token = tokenRedisRepository.findById(id).orElse(new TokenKey());
        return token.getAuth();
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        var tokens = tokenRedisRepository.findAll();
        for (TokenKey thisToken : tokens) {
            if (hasToken(thisToken.getAuth(), token, tokenType)) {
                return thisToken.getAuth();
            }
        }
        return null;
    }

    private static boolean hasToken(OAuth2Authorization authorization, String token, @Nullable OAuth2TokenType tokenType) {
        if (tokenType == null) {
            return matchesState(authorization, token) ||
                    matchesAuthorizationCode(authorization, token) ||
                    matchesAccessToken(authorization, token) ||
                    matchesIdToken(authorization, token) ||
                    matchesRefreshToken(authorization, token) ||
                    matchesDeviceCode(authorization, token) ||
                    matchesUserCode(authorization, token);
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            return matchesState(authorization, token);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            return matchesAuthorizationCode(authorization, token);
        } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            return matchesAccessToken(authorization, token);
        } else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
            return matchesIdToken(authorization, token);
        } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            return matchesRefreshToken(authorization, token);
        } else if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
            return matchesDeviceCode(authorization, token);
        } else if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
            return matchesUserCode(authorization, token);
        }
        return false;
    }

    private static boolean matchesState(OAuth2Authorization authorization, String token) {
        return token.equals(authorization.getAttribute(OAuth2ParameterNames.STATE));
    }

    private static boolean matchesAuthorizationCode(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);
        return authorizationCode != null && authorizationCode.getToken().getTokenValue().equals(token);
    }

    private static boolean matchesAccessToken(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
                authorization.getToken(OAuth2AccessToken.class);
        return accessToken != null && accessToken.getToken().getTokenValue().equals(token);
    }

    private static boolean matchesRefreshToken(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
                authorization.getToken(OAuth2RefreshToken.class);
        return refreshToken != null && refreshToken.getToken().getTokenValue().equals(token);
    }

    private static boolean matchesIdToken(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OidcIdToken> idToken =
                authorization.getToken(OidcIdToken.class);
        return idToken != null && idToken.getToken().getTokenValue().equals(token);
    }

    private static boolean matchesDeviceCode(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode =
                authorization.getToken(OAuth2DeviceCode.class);
        return deviceCode != null && deviceCode.getToken().getTokenValue().equals(token);
    }

    private static boolean matchesUserCode(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2UserCode> userCode =
                authorization.getToken(OAuth2UserCode.class);
        return userCode != null && userCode.getToken().getTokenValue().equals(token);
    }
}
