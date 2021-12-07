package com.tomboja.springbootjwtapp.config;

import com.tomboja.springbootjwtapp.filter.CustomAuthenticationFilter;
import com.tomboja.springbootjwtapp.filter.CustomAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

/**
 * @ProjectName: spring boot security with jwt authentication and authorization
 * @Author: tdessalegn
 * @Date: 12/4/21
 */
/**
 * This class is to manage the users and their roles.
 * To tell spring which users to use and what their roles are
 */
@Configuration // So that spring picks this up as a configuration class
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // make UserService implement UserDetailsService and override the one method in there
    private final UserDetailsService userDetailsService;

    // Create Bean for this at the application main starting point
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    /**
     * Tells spring what users to use and where to look for them
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // User detailed service is used to look for users
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Though not that necessary, we can customize the login url to whatever we like from the
        // default '/login'
        CustomAuthenticationFilter customAuthenticationFilter
                = new CustomAuthenticationFilter(authenticationManagerBean());
        customAuthenticationFilter.setFilterProcessesUrl("/api/login");
        // Disable cross-site-request-forgery
        http.csrf().disable();
        // Make request session to be stateless
        http.sessionManagement().sessionCreationPolicy(STATELESS);

        // If we want to allow all requests for example, for '/api/login' or refresh token path, permit all
        http.authorizeRequests().antMatchers("/api/login/**", "/api/token/refresh").permitAll();

        // requests coming to "/api/user/**" need ROLE_USER role
        http.authorizeRequests()
                .antMatchers(GET, "/api/user/**")
                .hasAnyAuthority("ROLE_USER");

        // requests coming to "/api/user/save/**" need ROLE_ADMIN role
        http.authorizeRequests()
                .antMatchers(POST, "/api/user/save/**")
                .hasAnyAuthority("ROLE_ADMIN");


        // Authenticate all requests
        http.authorizeRequests().anyRequest().authenticated();
        // Add request filter
        http.addFilter(customAuthenticationFilter);

        // Add the authorization filter
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
