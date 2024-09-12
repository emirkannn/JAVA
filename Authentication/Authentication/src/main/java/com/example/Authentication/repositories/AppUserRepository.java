package com.example.Authentication.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.Authentication.models.AppUser;

public interface AppUserRepository extends JpaRepository<AppUser, Integer> {

	public AppUser findByEmail(String email);
}
