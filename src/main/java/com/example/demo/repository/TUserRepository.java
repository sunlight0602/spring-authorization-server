package com.example.demo.repository;

import com.example.demo.entity.TUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public class TUserRepository extends JpaRepository<TUser, Long> {
    Optional<TUser> findByUsername(String username);
}
