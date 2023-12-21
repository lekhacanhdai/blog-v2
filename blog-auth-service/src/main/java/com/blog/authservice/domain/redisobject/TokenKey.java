package com.blog.authservice.domain.redisobject;

import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

/**
 * @author dai.le-anh
 * @since 12/20/2023
 */

@RedisHash("access_token")
@NoArgsConstructor
@Getter
@Setter
public class TokenKey {
    @Id
    private String id;
    private OAuth2Authorization auth;
}
