package com.tomboja.springbootjwtapp.domain;

import lombok.*;

import javax.persistence.*;
import java.util.Collection;

/**
 * @ProjectName: spring boot security with jwt authentication and authorization
 * @Author: tdessalegn
 * @Date: 12/4/21
 */

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id", nullable = false)
    private Long id;
    private String firstname;
    private String lastname;
    private String username;
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    private Collection<Role> roles;
}
