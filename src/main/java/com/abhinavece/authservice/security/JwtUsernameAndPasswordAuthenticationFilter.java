package com.abhinavece.authservice.security;

import com.abhinavece.authservice.config.JwtConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.stream.Collectors;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // Use AuthManager to validate the user credentials
    private AuthenticationManager authManager;

    @Autowired
    private JwtConfig jwtConfig;

    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager, JwtConfig jwtConfig) {
        this.authManager =authenticationManager;
        this.jwtConfig =jwtConfig;

        // By default JwtUsernameAndPasswordAuthenticationFilter listens "/login" path
        // In our case, we will user "/auth" path
        this.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher(jwtConfig.getUri(), "POST"));
    }

    // Attempt the authentication


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        try {
            // 1. Get credentials from request
            UserCredentials creds = new ObjectMapper().readValue(request.getInputStream(), UserCredentials.class);

            // 2. Create auth object (contains credentials) which will be used by auth manager
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(creds.getUsername(), creds.getPassword(), Collections.emptyList());

            // 3. Authentication manager authenticate the user,
            // and use UserDetailsServiceImpl::loadUserByUsername() method to load the user.
            return authManager.authenticate(authToken);

        }catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    // Upon successful authentication, generate a token.
    // The 'auth' passed to successfulAuthentication() is the current authenticated user.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication auth) throws IOException, ServletException {
        Long now = System.currentTimeMillis();
        String token = Jwts.builder()
                            .setSubject(auth.getName())
                            // Convert to list of strings.
                            // This is important because it affects the way we get them back in the Gateway.
                            .claim("authorities",auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                            .setIssuedAt(new Date(now))
                            .setExpiration(new Date(now + jwtConfig.getExpiration()*1000))
                            .signWith(SignatureAlgorithm.HS512, jwtConfig.getSecret().getBytes())
                            .compact();

        // Add token to header
        response.addHeader(jwtConfig.getHeader(), jwtConfig.getPrefix()+token);
    }


}
