package com.blog.authservice.domain.mapper;

import com.blog.authservice.domain.entity.UserEntity;
import com.blog.authservice.service.security.MyUserDetails;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

/**
 * @author dai.le-anh
 * @since 12/19/2023
 */

public class UserMapper {
    public static MyUserDetails map(UserEntity user){
        var userDetail = new MyUserDetails(user.getUsername(), user.getPassword(), List.of(new SimpleGrantedAuthority(user.getRole().getRole())));
        userDetail.setUserId(user.getUserId());
        userDetail.setEmail(user.getEmail());
        userDetail.setIsActive(user.getIsActive());
        return userDetail;
    }
}
