package com.itdifferentcources.internetprovider.jwt.services;

import com.itdifferentcources.internetprovider.jwt.persistence.entity.User;
import com.itdifferentcources.internetprovider.jwt.persistence.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public User loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException(String.format("User with username %s not found", username)));
    }
}
