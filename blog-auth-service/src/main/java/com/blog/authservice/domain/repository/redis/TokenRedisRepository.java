package com.blog.authservice.domain.repository.redis;

import com.blog.authservice.domain.redisobject.TokenKey;

/**
*@author dai.le-anh
*@since 12/20/2023
*/

public interface TokenRedisRepository extends RedisRepository<TokenKey, String> {
}
