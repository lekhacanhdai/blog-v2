package com.blog.authservice.domain.redisobject;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.util.SpringAuthorizationServerVersion;

import java.io.Serializable;
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
    private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;
    private String id;
    private String registeredClientId;
    private String principalName;
    private AuthorizationGrantType authorizationGrantType;
    private Set<String> authorizedScopes;
    private Map<String, Object> attributes;
    Map<String, OAuth2Authorization.Token<?>> tokens;


    public static CustomOAuth2Authorization fromOAuth2Authorization(OAuth2Authorization oAuth2Authorization, Class<?> authClass) {
        CustomOAuth2Authorization custom = new CustomOAuth2Authorization();
        custom.setId(oAuth2Authorization.getId());
        custom.setAuthorizedScopes(oAuth2Authorization.getAuthorizedScopes());
        custom.setRegisteredClientId(oAuth2Authorization.getRegisteredClientId());
        custom.setPrincipalName(oAuth2Authorization.getPrincipalName());
        custom.setAuthorizationGrantType(oAuth2Authorization.getAuthorizationGrantType());
        custom.setAttributes(oAuth2Authorization.getAttributes());
        if (authClass.toString().endsWith("OAuth2AuthorizationCode")) {
            custom.getTokens().put(authClass.getName(), oAuth2Authorization.getToken(authClass.getName()));
        }

        return custom;
    }

}
