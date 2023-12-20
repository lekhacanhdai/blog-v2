package com.blog.authservice.domain.repository.redis;

import org.springframework.data.repository.CrudRepository;

/**
 * @author dai.le-anh
 * @since 12/20/2023
 */

public interface RedisRepository<T, ID> extends CrudRepository<T, ID> {
}
