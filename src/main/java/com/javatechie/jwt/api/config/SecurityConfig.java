package com.javatechie.jwt.api.config;

import com.javatechie.jwt.api.filter.JwtFilter;
import com.javatechie.jwt.api.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends
    WebSecurityConfigurerAdapter {

 @Autowired
 private CustomUserDetailsService userDetailsService;

 @Autowired
 private JwtFilter jwtFilter;

 /*~~(Migrate manually based on https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter)~~>*/@Override
 protected void configure(
     AuthenticationManagerBuilder auth)
     throws Exception {
  auth.userDetailsService(
      userDetailsService);
 }

 /*~~(Migrate manually based on https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter)~~>*/@Bean(name = BeanIds.AUTHENTICATION_MANAGER)
 @Override
 public AuthenticationManager authenticationManagerBean()
     throws Exception {
  return super.authenticationManagerBean();
 }

 @Override
 protected void configure(
     HttpSecurity http)
     throws Exception {
  http.csrf(csrf -> csrf
      .authorizeRequests(requests -> requests
          .requestMatchers("/authenticate")
          .permitAll()
          .anyRequest()
          .authenticated())
      .exceptionHandling(withDefaults())
      .sessionManagement(management -> management
          .sessionCreationPolicy(
              SessionCreationPolicy.STATELESS)));
  http.addFilterBefore(
      jwtFilter,
      UsernamePasswordAuthenticationFilter.class);
 }

 @Bean
 public PasswordEncoder passwordEncoder() {
  return NoOpPasswordEncoder.getInstance();
 }
}
