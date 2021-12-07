package com.tomboja.springbootjwtapp.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tomboja.springbootjwtapp.domain.AppUser;
import com.tomboja.springbootjwtapp.domain.Role;
import com.tomboja.springbootjwtapp.service.UserService;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * @ProjectName: spring boot security with jwt authentication and authorization
 * @Author: tdessalegn
 * @Date: 12/4/21
 */

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<AppUser>> getUsers() {
        URI uri = URI
                .create(ServletUriComponentsBuilder
                .fromCurrentContextPath()
                .path("/api/users").toUriString());
        log.info("==========================");
        log.info("GetMapping url {} ", uri);
        log.info("==========================");
        return  ResponseEntity
                .created(uri) // This is to make the response status be 201
                .body(userService.getAllUsers()); // Add payload in the response body
    }

    @PostMapping("/users")
    public ResponseEntity<AppUser> saveUser(@RequestBody AppUser user) {
        URI uri = URI
                .create(ServletUriComponentsBuilder
                        .fromCurrentContextPath()
                        .path("/api/users").toUriString());
        log.info("==========================");
        log.info("PostMapping url {} ", uri);
        log.info("==========================");
        return ResponseEntity
                .created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/role")
    public ResponseEntity<Role> addRole (Role role) {
        URI uri = URI
                .create(ServletUriComponentsBuilder
                        .fromCurrentContextPath()
                        .path("/api/role").toUriString());
        log.info("==========================");
        log.info("PostMapping url {} ", uri);
        log.info("==========================");
        return ResponseEntity
                .created(uri).body(userService.saveRole(role));
    }


    @PostMapping("/{username}/{role}")
    public ResponseEntity<?> addRoleToUser(
            @PathVariable("username") String username,
            @PathVariable("role") String role) {
        RoleToUserForm roleToUserForm = new RoleToUserForm(username, role);
        boolean roleAdded = userService.addRoleToAppUser(
                roleToUserForm.getUsername(),
                roleToUserForm.getRolename());
        if (roleAdded) {
            log.info("role {} successfully added for user {}", role, username);
            return ResponseEntity.ok().build();
        }else {
            log.error("Adding role {} for user {} failed.", role, username);
            return ResponseEntity.badRequest().build();
        }
    }

    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorization = request.getHeader(AUTHORIZATION);
        if (authorization != null && authorization.startsWith("Bearer ")) {
            try {
                String refreshToken = authorization.substring("Bearer ".length());
                Algorithm algorithm = Algorithm.HMAC256("mySercret".getBytes());

                // Verify the token
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(refreshToken);
                String username = decodedJWT.getSubject();
                AppUser user = userService.getUserByUsername(username);

                String accessToken = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", user.getRoles().stream()
                                .map(Role::getRolename)
                                .collect(Collectors.toList()))
                        .sign(algorithm);

                // To pass the tokens in response body
                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", accessToken);
                tokens.put("refresh_token", refreshToken);

                // Set response contentType
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);

            } catch (Exception e) {
                log.error("Error logging in {}", e.getMessage());
                response.setHeader("error", e.getMessage());
                response.setStatus(FORBIDDEN.value());
                //response.sendError(FORBIDDEN.value());
                Map<String, String> error = new HashMap<>();
                error.put("error_message", e.getMessage());

                // Set response contentType
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }

        } else {
            throw new RuntimeException("Authorization refresh token not correct: {}" + authorization);
        }
    }


}
@Data
@AllArgsConstructor
class RoleToUserForm {
    private String username;
    private String rolename;
}