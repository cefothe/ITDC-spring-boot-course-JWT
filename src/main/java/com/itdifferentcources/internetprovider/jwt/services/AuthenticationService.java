package com.itdifferentcources.internetprovider.jwt.services;

import com.itdifferentcources.internetprovider.jwt.services.util.JwtUtils;
import com.itdifferentcources.internetprovider.jwt.persistence.entity.Role;
import com.itdifferentcources.internetprovider.jwt.persistence.entity.Role.RoleType;
import com.itdifferentcources.internetprovider.jwt.persistence.entity.User;
import com.itdifferentcources.internetprovider.jwt.persistence.repository.RoleRepository;
import com.itdifferentcources.internetprovider.jwt.persistence.repository.UserRepository;
import com.itdifferentcources.internetprovider.jwt.services.dto.JwtResponseDTO;
import com.itdifferentcources.internetprovider.jwt.services.dto.LoginRequestDTO;
import com.itdifferentcources.internetprovider.jwt.services.dto.SignupRequestDTO;
import com.itdifferentcources.internetprovider.jwt.services.exception.UsernameAlreadyExist;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;


    private static final Map<RoleType, Role>  roles = new HashMap<>();

    @PostConstruct
    protected void postConstruct(){
        roleRepository.findAll().stream()
            .forEach(role -> roles.put(role.getName(), role));
    }

    public void signup(SignupRequestDTO createUserDto) {
        Role role = roles.get(RoleType.ROLE_CUSTOMER);
        if(userRepository.count() == 0){
            role = roles.get(RoleType.ROLE_ADMIN);
        }
        if(userRepository.findByUsername(createUserDto.getUsername()).isPresent()){
         throw new UsernameAlreadyExist(String.format("Username %s already exist", createUserDto.getUsername()));
        }
        User user = new User(createUserDto.getUsername(), passwordEncoder.encode(createUserDto.getPassword()), createUserDto.getEmail(),
            Set.of(role));
        userRepository.save(user);
    }

    public JwtResponseDTO signin(LoginRequestDTO loginRequestDTO) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(loginRequestDTO.getUsername(), loginRequestDTO.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        return new JwtResponseDTO(jwt);
    }
}
