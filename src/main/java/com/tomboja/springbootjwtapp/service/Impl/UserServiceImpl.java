package com.tomboja.springbootjwtapp.service.Impl;

import com.tomboja.springbootjwtapp.domain.AppUser;
import com.tomboja.springbootjwtapp.domain.Role;
import com.tomboja.springbootjwtapp.repository.RoleRepository;
import com.tomboja.springbootjwtapp.repository.UserRepository;
import com.tomboja.springbootjwtapp.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * @ProjectName: spring boot security with jwt authentication and authorization
 * @Author: tdessalegn
 * @Date: 12/4/21
 */

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public AppUser saveUser(AppUser user) {
        log.info("Saving new user `{}` to the database...", user.getUsername());
        user.setPassword(passwordEncoder.encode(user.getPassword())); // Encode password before saving
        return userRepository.save(user);
    }

    @Override
    public AppUser getUserByUsername(String username) {
        log.info("Getting user `{}` from the database...", username);
        return userRepository.findByUsername(username);
    }

    @Override
    public List<AppUser> getAllUsers() {
        log.info("Fetching all the users from the database...");
        return userRepository.findAll();
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving new role `{}` to the database...", role.getRolename());
        return roleRepository.save(role);
    }

    @Override
    public boolean addRoleToAppUser(String username, String roleName) {
        log.info("Adding new role `{}` to user `{}` in the database...", roleName, username);
        AppUser user = userRepository.findByUsername(username);
        Role role = roleRepository.findByRolename(roleName);
        return user.getRoles().add(role);
    }

    /**
     * Spring uses this method to load users from db or wherever we specify for it to get it
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser user = userRepository.findByUsername(username);
        if (user == null) {
            log.error("User with username {} is not found in database... ", username);
            throw new UsernameNotFoundException("User not found!!");
        } else {
            log.info("User with username {} is found in database... ", username);
        }

        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role ->
                authorities.add(new SimpleGrantedAuthority(role.getRolename())));
        return new User(user.getUsername(), user.getPassword(), authorities);
    }
}
