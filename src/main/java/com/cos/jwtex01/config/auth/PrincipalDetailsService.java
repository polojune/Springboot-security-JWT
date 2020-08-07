package com.cos.jwtex01.config.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.cos.jwtex01.model.User;
import com.cos.jwtex01.repository.UserRepository;

@Service
public class PrincipalDetailsService implements UserDetailsService{
    
	@Autowired
	private UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		System.out.println("PrincipalService: 진입");
		System.out.println(username);
		User user = userRepository.findByUsername(username);
		
		if(user == null) {
			System.out.println("user null");
		}
		return new PrincipalDetails(user);
		
	} 
   
	
}
