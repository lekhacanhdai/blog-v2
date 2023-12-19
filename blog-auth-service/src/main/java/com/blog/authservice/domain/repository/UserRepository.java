package com.blog.authservice.domain.repository;

import com.blog.authservice.domain.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * @author dai.le-anh
 * @since 12/19/2023
 */

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Long> {

    @Query("SELECT u FROM UserEntity u " +
            "LEFT JOIN FETCH u.role " +
            "WHERE u.username = :username")
    Optional<UserEntity> findByUsernameFetchRole(@Param("username") String username);
}
