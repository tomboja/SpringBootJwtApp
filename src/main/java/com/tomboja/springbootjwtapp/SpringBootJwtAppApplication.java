package com.tomboja.springbootjwtapp;

import com.tomboja.springbootjwtapp.domain.AppUser;
import com.tomboja.springbootjwtapp.domain.Role;
import com.tomboja.springbootjwtapp.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SpringBootJwtAppApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringBootJwtAppApplication.class, args);
    }

    // Create password encoder so that when application starts spring picks-up password encoder bean
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner run(UserService us) {
        return args -> {
            // Add Users
            us.saveUser(new AppUser(null, "James", "Tollu", "jtollu", "Tollu123", new ArrayList<>()));
            us.saveUser(new AppUser(null, "Jason", "Bourne", "jbourne", "Bourne123", new ArrayList<>()));
            us.saveUser(new AppUser(null, "Will", "Smith", "wsmith", "Smith123", new ArrayList<>()));
            us.saveUser(new AppUser(null, "Tom", "Boja", "tboja", "Boja123", new ArrayList<>()));

            // Add Roles
            us.saveRole(new Role(null, "ROLE_USER"));
            us.saveRole(new Role(null, "ROLE_MANAGER"));
            us.saveRole(new Role(null, "ROLE_ADMIN"));
            us.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            // Add role to user
            us.addRoleToAppUser("jtollu", "ROLE_USER");
            us.addRoleToAppUser("jbourne", "ROLE_MANAGER");
            us.addRoleToAppUser("wsmith", "ROLE_SUPER_ADMIN");
            us.addRoleToAppUser("tboja", "ROLE_ADMIN");
            us.addRoleToAppUser("wsmith", "ROLE_ADMIN");

        };
    }
}
