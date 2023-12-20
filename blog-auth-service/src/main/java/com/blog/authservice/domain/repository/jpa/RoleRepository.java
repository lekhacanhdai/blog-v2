package com.blog.authservice.domain.repository.jpa;

import com.blog.authservice.domain.entity.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * @author dai.le-anh
 * @since 12/19/2023
 */

@Repository
public interface RoleRepository extends JpaRepository<RoleEntity, Long> {
}
