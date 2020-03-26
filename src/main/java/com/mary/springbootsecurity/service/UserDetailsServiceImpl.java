package com.mary.springbootsecurity.service;


import com.mary.springbootsecurity.model.User;
import com.mary.springbootsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User " + username + " Not Found"));

        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
                AuthorityUtils.createAuthorityList(user.getRole().getName()));
    }

    @Transactional(readOnly = true)
    public UserDetails loadUserByUsernameAndPassword(String username, String password) throws UsernameNotFoundException {
        User user = userRepository.findByUsernameAndPassword(username, password).orElseThrow(() -> new UsernameNotFoundException("User " + username + " Not Found"));

        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
                        AuthorityUtils.createAuthorityList(user.getRole().getName()));
    }

}
