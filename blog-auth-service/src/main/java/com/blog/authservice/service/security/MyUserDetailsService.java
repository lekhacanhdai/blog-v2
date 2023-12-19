package com.blog.authservice.service.security;

import com.blog.authservice.domain.mapper.UserMapper;
import com.blog.authservice.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * @author dai.le-anh
 * @since 12/19/2023
 */

//@Service
@RequiredArgsConstructor
public class MyUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public MyUserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var user = userRepository.findByUsernameFetchRole(username).orElseThrow(() ->
                new UsernameNotFoundException(username));
        return UserMapper.map(user);
    }
}
