package com.mary.springbootsecurity.controller;

import com.mary.springbootsecurity.service.UserDetailsServiceImpl;
import com.mary.springbootsecurity.util.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

@Controller
public class HomeController {

    @Autowired
    JwtUtil jwtUtil;
    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @GetMapping("/home")
    public String home() {
        return "home";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/403")
    public String accessDenied() {
        return "403";
    }

    @PostMapping("/auth")
    public String auth(@RequestParam String username, @RequestParam String password, HttpServletResponse httpServletResponse) throws Exception {
        Cookie cookie = new Cookie("Authorization", jwtUtil.generateToken(userDetailsService.loadUserByUsernameAndPassword(username, password)));
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        httpServletResponse.addCookie(cookie);
        return "redirect:/home";
    }

    @GetMapping("/")
    public String login(@RequestParam(required = false, name = "error") String error, @RequestParam(required = false, name = "logout") String logout, Model model,
                        @CookieValue(value = "Authorization", required = false) String cookie) {

        UserDetails userDetails = null;
        try {
            userDetails = cookie != null ? userDetailsService.loadUserByUsername(jwtUtil.extractUsername(cookie)) : null;
        } catch (ExpiredJwtException ex) {
            return "login";
        }

        if (error != null)
            model.addAttribute("error", true);
        else if (logout != null)
            model.addAttribute("logout", true);

        return userDetails == null ? "login" : "redirect:/home";
    }
}
