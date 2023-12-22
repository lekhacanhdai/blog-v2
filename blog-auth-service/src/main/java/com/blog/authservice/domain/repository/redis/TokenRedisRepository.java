package com.blog.authservice.domain.repository.redis;

import com.blog.authservice.domain.redisobject.CustomOAuth2Authorization;
import com.blog.authservice.domain.redisobject.TokenKey;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
*@author dai.le-anh
*@since 12/20/2023
*/

@Repository
public interface TokenRedisRepository extends CrudRepository<CustomOAuth2Authorization, String> {
    CustomOAuth2Authorization findByAuthorizationCodeValueEqualsOrAccessTokenValueEqualsOrRefreshTokenValueEqualsOrOIDCIdTokenValueEqualsOrUserCodeValueEqualsOrDeviceCodeValueEquals(
            String authorizationCodeValue,
            String accessTokenValue,
            String refreshTokenValue,
            String oIDCIdTokenValue,
            String userCodeValue,
            String deviceCodeValue
    );

    CustomOAuth2Authorization findByAuthorizationCodeValue(String authorizationCodeValue);
    CustomOAuth2Authorization findByAccessTokenValue(String accessTokenValue);
    CustomOAuth2Authorization findByRefreshTokenValue(String refreshTokenValue);
    CustomOAuth2Authorization findByOIDCIdTokenValue(String oIDCIdTokenValue);
    CustomOAuth2Authorization findByUserCodeValue(String userCodeValue);
    CustomOAuth2Authorization findByDeviceCodeValue(String deviceCodeValue);
    CustomOAuth2Authorization findByState(String state);
}
