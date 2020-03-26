package com.mary.springbootsecurity.config;

import com.mary.springbootsecurity.service.UserDetailsServiceImpl;
import com.mary.springbootsecurity.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    @Autowired
    private JwtUtil jwtTokenUtil;

    private static final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("path: " + request.getServletPath() + " " + request.getMethod());

        List<String> excludeUrlPatterns = Arrays.asList("/js/**", "/css/**", "/images/**", "/webjars/**", "**/.jpg", "/favicon.ico", "/auth", "/");
        if (excludeUrlPatterns.stream().anyMatch(p -> pathMatcher.match(p, request.getServletPath()))) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = Arrays.stream(request.getCookies())
                .filter(c -> c.getName().equals("Authorization"))
                .findFirst()
                .map(Cookie::getValue)
                .orElse(null);

        if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(jwtTokenUtil.extractUsername(token));
            if (jwtTokenUtil.validateToken(token, userDetails)) {
                SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(userDetails.getUsername(), userDetails.getPassword(), userDetails.getAuthorities()));
            }
        }

        filterChain.doFilter(request, response);
    }
}
