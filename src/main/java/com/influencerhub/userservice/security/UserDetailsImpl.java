package com.influencerhub.userservice.security;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.influencerhub.userservice.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections; // For simplicity, no roles yet
// import java.util.List;
// import java.util.stream.Collectors;

public class UserDetailsImpl implements UserDetails {
    private static final long serialVersionUID = 1L;

    private Long id;
    private String username;
    @JsonIgnore
    private String password;
    private boolean enabled;
    // private Collection<? extends GrantedAuthority> authorities; // If using roles

    public UserDetailsImpl(Long id, String username, String password, boolean enabled /*, Collection<? extends GrantedAuthority> authorities */) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.enabled = enabled;
        // this.authorities = authorities;
    }

    public static UserDetailsImpl build(User user) {
        // List<GrantedAuthority> authorities = user.getRoles().stream() // If using roles
        //         .map(role -> new SimpleGrantedAuthority(role))
        //         .collect(Collectors.toList());

        return new UserDetailsImpl(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                user.isEnabled()
                // authorities // If using roles
        );
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // return authorities; // If using roles
        return Collections.emptyList(); // No roles for now
    }

    public Long getId() {
        return id;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}