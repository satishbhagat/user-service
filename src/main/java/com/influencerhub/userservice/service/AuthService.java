package com.influencerhub.userservice.service;

import com.influencerhub.userservice.dto.AuthResponse;
import com.influencerhub.userservice.dto.LoginRequest;
import com.influencerhub.userservice.dto.RegisterRequest;
import com.influencerhub.userservice.entity.User;
import com.influencerhub.userservice.repository.UserRepository;
import com.influencerhub.userservice.security.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    public User registerUser(RegisterRequest registerRequest) {
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            throw new RuntimeException("Error: Username is already taken!"); // Use custom exceptions later
        }

        User user = new User();
        user.setUsername(registerRequest.getUsername());
        user.setPassword(encoder.encode(registerRequest.getPassword()));
        // Set roles if you have them
        return userRepository.save(user);
    }

    public AuthResponse loginUser(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        // UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal(); // If you need more details from UserDetailsImpl
        return new AuthResponse(jwt, loginRequest.getUsername());
    }
}