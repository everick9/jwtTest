package com.javatechie.streaming.repository;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import com.javatechie.streaming.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
   @EntityGraph(attributePaths = "authorities")
   Optional<User> findOneWithAuthoritiesByUsername(String username);
}