package com.tomboja.springbootjwtapp.service;

import com.tomboja.springbootjwtapp.domain.AppUser;
import com.tomboja.springbootjwtapp.domain.Role;

import java.util.List;

/**
 * @ProjectName: spring boot security with jwt authentication and authorization
 * @Author: tdessalegn
 * @Date: 12/4/21
 */

public interface UserService {
    AppUser saveUser(AppUser user);
    AppUser getUserByUsername(String username);
    List<AppUser> getAllUsers();

    Role saveRole(Role role);
    boolean addRoleToAppUser(String username, String roleName);

}
