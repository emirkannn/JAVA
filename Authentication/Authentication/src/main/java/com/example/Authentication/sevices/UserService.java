package com.example.Authentication.sevices;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.Authentication.models.AppUser;
import com.example.Authentication.repositories.AppUserRepository;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private AppUserRepository repo;
    
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        AppUser appUser = repo.findByEmail(email);
        
        if (appUser == null) {
            throw new UsernameNotFoundException("User with email " + email + " not found.");
        }
        
        return User.withUsername(appUser.getEmail())
                   .password(appUser.getPassword())
                   .roles(appUser.getRole())
                   .build();
    }
}

