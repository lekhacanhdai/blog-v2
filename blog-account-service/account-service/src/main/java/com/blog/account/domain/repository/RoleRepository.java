package com.blog.account.domain.repository;

import com.blog.account.domain.entity.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * @author dai.le-anh
 * @since 10/27/2023
 */

@Repository
public interface RoleRepository extends JpaRepository<RoleEntity, Long> {
}
