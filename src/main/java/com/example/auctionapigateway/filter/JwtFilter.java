package com.example.auctionapigateway.filter;

import org.hibernate.annotations.Comment;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private final String JWT_SECRET;

    private final String JWT_COOKIE_NAME;

    public JwtFilter(Environment env) {
        JWT_SECRET = env.getProperty("jwt.secret");
        JWT_COOKIE_NAME = env.getProperty("jwt.cookieName");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

    }
}
