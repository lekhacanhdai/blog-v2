package com.blog.authservice.config;

import com.blog.authservice.domain.redisobject.CustomOAuth2Authorization;
import com.blog.authservice.domain.repository.redis.TokenRedisRepository;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;


import java.lang.reflect.Method;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * @author dai.le-anh
 * @since 12/21/2023
 */

public final class CustomOAuth2AuthorizationService implements OAuth2AuthorizationService {
    private final TokenRedisRepository tokenRedisRepository;
    private final RegisteredClientRepository registeredClientRepository;
    public CustomOAuth2AuthorizationService(TokenRedisRepository tokenRedisRepository, RegisteredClientRepository registeredClientRepository) {
        this.tokenRedisRepository = tokenRedisRepository;
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        CustomOAuth2Authorization customOAuth2Authorization = new CustomOAuth2Authorization();
        customOAuth2Authorization.setId(customOAuth2Authorization.getId());
        customOAuth2Authorization.setAuthorizedScopes(customOAuth2Authorization.getAuthorizedScopes());
        customOAuth2Authorization.setAttributes(authorization.getAttributes());
        customOAuth2Authorization.setPrincipalName(authorization.getPrincipalName());
        customOAuth2Authorization.setRegisteredClientId(authorization.getRegisteredClientId());
        customOAuth2Authorization.setAuthorizationGrantType(authorization.getAuthorizationGrantType().getValue());
        customOAuth2Authorization.setState(authorization.getAttribute(OAuth2ParameterNames.STATE));
        mapAuthenticationToken(authorization, customOAuth2Authorization);
        tokenRedisRepository.save(customOAuth2Authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        var key = tokenRedisRepository.findById(authorization.getId());
        key.ifPresent(tokenRedisRepository::delete);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        var token = tokenRedisRepository.findById(id).orElse(null);
        return mapToToken(token);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        CustomOAuth2Authorization customOAuth2Authorization = null;
        if (tokenType == null) {
            customOAuth2Authorization = tokenRedisRepository.findByAuthorizationCodeValueEqualsOrAccessTokenValueEqualsOrRefreshTokenValueEqualsOrOIDCIdTokenValueEqualsOrUserCodeValueEqualsOrDeviceCodeValueEquals(
                    token, token, token, token, token, token
            );
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            customOAuth2Authorization = tokenRedisRepository.findByState(token);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            customOAuth2Authorization = tokenRedisRepository.findByAuthorizationCodeValue(token);
        } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            customOAuth2Authorization = tokenRedisRepository.findByAccessTokenValue(token);
        } else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
            customOAuth2Authorization = tokenRedisRepository.findByOIDCIdTokenValue(token);
        } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            customOAuth2Authorization = tokenRedisRepository.findByRefreshTokenValue(token);
        } else if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
            customOAuth2Authorization = tokenRedisRepository.findByUserCodeValue(token);
        } else if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
            customOAuth2Authorization = tokenRedisRepository.findByDeviceCodeValue(token);
        }
        if (token != null){
            return mapToToken(customOAuth2Authorization);
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

    private void mapAuthenticationToken(OAuth2Authorization authorization, CustomOAuth2Authorization customOAuth2Authorization){
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);
        mapTokenParams(authorizationCode, "authorizationCode", customOAuth2Authorization);
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
                authorization.getToken(OAuth2AccessToken.class);
        mapTokenParams(accessToken, "accessToke", customOAuth2Authorization);
        if (accessToken != null) {
            var accessTokenType = accessToken.getToken().getTokenType().getValue();
            if (!CollectionUtils.isEmpty(accessToken.getToken().getScopes())) {
                var accessTokenScopes = StringUtils.collectionToDelimitedString(accessToken.getToken().getScopes(), ",");
                customOAuth2Authorization.setAccessTokenScopes(accessTokenScopes);
            }
            customOAuth2Authorization.setAccessTokenType(accessTokenType);

        }
        OAuth2Authorization.Token<OidcIdToken> oIDCIdToken =
                authorization.getToken(OidcIdToken.class);
        mapTokenParams(oIDCIdToken, "oIDCIdToken", customOAuth2Authorization);
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
                authorization.getToken(OAuth2RefreshToken.class);
        mapTokenParams(refreshToken, "refreshToken", customOAuth2Authorization);
        OAuth2Authorization.Token<OAuth2UserCode> userCode =
                authorization.getToken(OAuth2UserCode.class);
        mapTokenParams(userCode, "userCode", customOAuth2Authorization);
        OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode =
                authorization.getToken(OAuth2DeviceCode.class);
        mapTokenParams(deviceCode, "deviceCode", customOAuth2Authorization);
    }

    private void mapTokenParams(OAuth2Authorization.Token<?> token, String tokenType, CustomOAuth2Authorization customOAuth2Authorization) {
        if (token != null){
            try {
                Class<?> customOAuth2Class = CustomOAuth2Authorization.class;
                Method setValueMethod = customOAuth2Class.getMethod("set" + tokenType + "Value", String.class);
                Method setIssuedAt = customOAuth2Class.getMethod(tokenType + "IssuedAt", Timestamp.class);
                Method setExpiredAt = customOAuth2Class.getMethod(tokenType + "ExpiredAt", Timestamp.class);
                Method setMetadata = customOAuth2Class.getMethod(tokenType + "Metadata", Map.class);
                setValueMethod.invoke(customOAuth2Authorization, token.getToken().getTokenValue());
                if (token.getToken().getIssuedAt() != null) {
                    setIssuedAt.invoke(customOAuth2Authorization, Timestamp.from(token.getToken().getIssuedAt()));
                }
                if (token.getToken().getExpiresAt() != null) {
                    setExpiredAt.invoke(customOAuth2Authorization, Timestamp.from(token.getToken().getExpiresAt()));
                }
                if (token.getMetadata() != null){
                    setMetadata.invoke(customOAuth2Authorization, token.getMetadata());
                }
            } catch (Exception e){
                e.printStackTrace();
            }
        }
    }

    @SuppressWarnings("unchecked")
    private OAuth2Authorization mapToToken(CustomOAuth2Authorization customOAuth2Authorization){
        var client = registeredClientRepository.findByClientId(customOAuth2Authorization.getRegisteredClientId());
        if (client == null) {
            throw new DataRetrievalFailureException(
                    "The RegisteredClient with id '" + customOAuth2Authorization.getRegisteredClientId() + "' was not found in the RegisteredClientRepository.");
        }
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(client);
        builder.id(customOAuth2Authorization.getId())
                .principalName(org.apache.commons.lang3.StringUtils.defaultString(customOAuth2Authorization.getPrincipalName()))
                .authorizedScopes(customOAuth2Authorization.getAuthorizedScopes())
                .authorizationGrantType(new AuthorizationGrantType(customOAuth2Authorization.getAuthorizationGrantType()))
                .attributes((attrs) -> attrs.putAll(customOAuth2Authorization.getAttributes()));
        if (StringUtils.hasText(customOAuth2Authorization.getState())){
            builder.attribute(OAuth2ParameterNames.STATE, customOAuth2Authorization.getState());
        }
        Instant tokenIssuedAt;
        Instant tokenExpiresAt;
        String authorizationCodeValue = customOAuth2Authorization.getAuthorizationCodeValue();

        if (StringUtils.hasText(authorizationCodeValue)){
            tokenIssuedAt = customOAuth2Authorization.getAuthorizationCodeIssuedAt().toInstant();
            tokenExpiresAt = customOAuth2Authorization.getAuthorizationCodeExpiredAt().toInstant();
            Map<String, Object> tokenMetadata = customOAuth2Authorization.getAuthorizationCodeMetadata();
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                    authorizationCodeValue, tokenIssuedAt, tokenExpiresAt);
            builder.token(authorizationCode, (metadata) -> metadata.putAll(tokenMetadata));
        }

        String accessTokenValue = customOAuth2Authorization.getAccessTokenValue();

        if (StringUtils.hasText(accessTokenValue)){
            tokenIssuedAt = customOAuth2Authorization.getAccessTokenIssuedAt().toInstant();
            tokenExpiresAt = customOAuth2Authorization.getAccessTokenExpiredAt().toInstant();
            Map<String, Object> tokenMetadata = customOAuth2Authorization.getAccessTokenMetadata();
            OAuth2AccessToken.TokenType tokenType = null;
            if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(customOAuth2Authorization.getAccessTokenType())) {
                tokenType = OAuth2AccessToken.TokenType.BEARER;
            }

            Set<String> scopes = Collections.emptySet();
            String accessTokenScopes = customOAuth2Authorization.getAccessTokenScopes();
            if (accessTokenScopes != null) {
                scopes = StringUtils.commaDelimitedListToSet(accessTokenScopes);
            }

            OAuth2AccessToken accessToken = new OAuth2AccessToken(tokenType, accessTokenValue, tokenIssuedAt, tokenExpiresAt, scopes);
            builder.token(accessToken, (metadata) -> metadata.putAll(tokenMetadata));
        }

        String oidcIdTokenValue = customOAuth2Authorization.getOIDCIdTokenValue();

        if (StringUtils.hasText(oidcIdTokenValue)){
            tokenIssuedAt = customOAuth2Authorization.getOIDCIdTokenIssuedAt().toInstant();
            tokenExpiresAt = customOAuth2Authorization.getOIDCIdTokenExpiredAt().toInstant();
            Map<String, Object> tokenMetadata = customOAuth2Authorization.getOIDCIdTokenMetadata();
            OidcIdToken oidcToken = new OidcIdToken(
                    oidcIdTokenValue, tokenIssuedAt, tokenExpiresAt, (Map<String, Object>) tokenMetadata.get(OAuth2Authorization.Token.CLAIMS_METADATA_NAME));
            builder.token(oidcToken, (metadata) -> metadata.putAll(tokenMetadata));
        }

        String refreshTokenValue = customOAuth2Authorization.getRefreshTokenValue();

        if (StringUtils.hasText(refreshTokenValue)){
            tokenIssuedAt = customOAuth2Authorization.getRefreshTokenIssuedAt().toInstant();
            var refreshExpired = customOAuth2Authorization.getRefreshTokenExpiredAt();
            tokenExpiresAt = null;
            if (refreshExpired != null){
                tokenExpiresAt = customOAuth2Authorization.getRefreshTokenExpiredAt().toInstant();
            }
            Map<String, Object> tokenMetadata = customOAuth2Authorization.getRefreshTokenMetadata();
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    refreshTokenValue, tokenIssuedAt, tokenExpiresAt);
            builder.token(refreshToken, (metadata) -> metadata.putAll(tokenMetadata));
        }

        String userCodeValue = customOAuth2Authorization.getUserCodeValue();

        if (StringUtils.hasText(userCodeValue)){
            tokenIssuedAt = customOAuth2Authorization.getUserCodeIssuedAt().toInstant();
            tokenExpiresAt = customOAuth2Authorization.getUserCodeExpiredAt().toInstant();
            Map<String, Object> tokenMetadata = customOAuth2Authorization.getUserCodeMetadata();
            OAuth2UserCode userCode = new OAuth2UserCode(
                    userCodeValue, tokenIssuedAt, tokenExpiresAt);
            builder.token(userCode, (metadata) -> metadata.putAll(tokenMetadata));
        }

        String deviceCodeValue = customOAuth2Authorization.getDeviceCodeValue();

        if (StringUtils.hasText(deviceCodeValue)){
            tokenIssuedAt = customOAuth2Authorization.getDeviceCodeIssuedAt().toInstant();
            tokenExpiresAt = customOAuth2Authorization.getDeviceCodeExpiredAt().toInstant();
            Map<String, Object> tokenMetadata = customOAuth2Authorization.getDeviceCodeMetadata();
            OAuth2DeviceCode deviceCode = new OAuth2DeviceCode(
                    deviceCodeValue, tokenIssuedAt, tokenExpiresAt);
            builder.token(deviceCode, (metadata) -> metadata.putAll(tokenMetadata));
        }
        return builder.build();
    }
}
