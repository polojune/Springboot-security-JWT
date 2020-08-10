package com.cos.jwtex01.controller;

import java.util.List;

import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.cos.jwtex01.config.auth.PrincipalDetails;
import com.cos.jwtex01.config.auth.SessionUser;
import com.cos.jwtex01.model.User;
import com.cos.jwtex01.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("api/v1")
//@CrossOrigin //CORS허용
public class RestApiController {
    
	
	private final UserRepository userRepository; 
	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@GetMapping("user")
	public String user(Authentication authentication) {
	    PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("principal:" + principal.getUser().getId());
		System.out.println("principal:" + principal.getUser().getUsername());
		System.out.println("principal:" + principal.getUser().getPassword());
		System.out.println("principal:" + principal.getUser().getRoles());
		
		return "<h1>user</h1>";
	}
	
	
	//모든 사람이 접근 가능
	@GetMapping("home") 
	public String home() {
		return "<h1>home</h1>";
	}
    //매니저 접근가능 
	@GetMapping("manager/reports")
	public String reports() {
		return "<h1>reports</h1>";
	}
    //관리자 접근 가능 
	@GetMapping("admin/users")
	public List<User> users() {
		return null;
	}
	
	@PostMapping("join")
	public String join(@RequestBody User user) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		userRepository.save(user);
		return "회원가입완료";
	}
}
