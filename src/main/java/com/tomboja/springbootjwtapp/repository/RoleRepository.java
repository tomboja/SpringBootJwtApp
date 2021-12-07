package com.tomboja.springbootjwtapp.repository;

import com.tomboja.springbootjwtapp.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @ProjectName: spring boot security with jwt authentication and authorization
 * @Author: tdessalegn
 * @Date: 12/4/21
 */

public interface RoleRepository extends JpaRepository<Role, Long> {

    // Tell Jpa to find role by role name
    Role findByRolename(String roleName);
}
