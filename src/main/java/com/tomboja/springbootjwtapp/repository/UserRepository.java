package com.tomboja.springbootjwtapp.repository;

import com.tomboja.springbootjwtapp.domain.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @ProjectName: spring boot security with jwt authentication and authorization
 * @Author: tdessalegn
 * @Date: 12/4/21
 */

public interface UserRepository extends JpaRepository<AppUser, Long> {

    // Jpa finds the user by username
    AppUser findByUsername(String username);
}
