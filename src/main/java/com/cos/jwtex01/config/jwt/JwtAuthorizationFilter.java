package com.cos.jwtex01.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwtex01.config.auth.PrincipalDetails;
import com.cos.jwtex01.config.auth.SessionUser;
import com.cos.jwtex01.model.User;
import com.cos.jwtex01.repository.UserRepository;

//인가
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private UserRepository userRepository;
	
	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
 
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
          String header = request.getHeader(JwtProperties.HEADER_STRING);
          if(header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) {
        	  chain.doFilter(request, response);
          }
		   String token = request.getHeader(JwtProperties.HEADER_STRING)
		       .replace(JwtProperties.TOKEN_PREFIX, "")
		       .replace(" ", "")
		       .replace("=", "");
		   
		   //5.토큰 검증(이게 인증이기때문에 AuthenticationManager필요없음)
		   //내가 securityContext에 직접 접근해서 세션을 만들때 자동으로 UserDetailsService에 있는 loadByUsername 호출 할필요없음
		 	 String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET))
		 			 .build()
		 			 .verify(token)
		 			 .getClaim("username").asString();
		 	   if(username !=null) {
		 		   User user = userRepository.findByUsername(username); 
		 		   
		 		   // 인증은 토큰 검증시 끝. 인증을 하기 위해서가 아닌 스프링 시큐리티가 수행해주는 권한 처리를 위해 
		 		   // 아래와 같이 토큰을 만들어서 Authentication 객체를 강제로 만들고 그걸 세션에 저장!
		 		   PrincipalDetails principalDetails = new PrincipalDetails(user);
		 		   Authentication authentication = new UsernamePasswordAuthenticationToken(
		 				   principalDetails,//나중에 컨트롤러에서 DI해서 쓸때 사용하기 편함. 
		 				   null,//패스워드는 모르니까 null 처리,어차리 지금 인증하는게 아니니까!!
		 				   principalDetails.getAuthorities());
		 	     //강제로 시큐리티의 세션에 접근하여 값 저장 
		 		   SecurityContextHolder.getContext().setAuthentication(authentication);
		 	   }
		       chain.doFilter(request, response);
		 	 
		 	  
		   }
	  
//		 	  private Authentication getUsernamePasswordAuthentication(HttpServletRequest request) {
//		 	        String token = request.getHeader(JwtProperties.HEADER_STRING)
//		 	                .replace(JwtProperties.TOKEN_PREFIX,"");
//
//		 	        if (token != null) {
//		 	            // parse the token and validate it
//		 	            String userName = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET.getBytes()))
//		 	                    .build()
//		 	                    .verify(token)
//		 	                    .getSubject();
//
//		 	            // Search in the DB if we find the user by token subject (username)
//		 	            // If so, then grab user details and create spring auth token using username, pass, authorities/roles
//		 	            if (userName != null) {
//		 	                User user = userRepository.findByUsername(userName);
//		 	               PrincipalDetails principal = new PrincipalDetails(user);
//		 	                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userName, null, principal.getAuthorities());
//		 	                return auth;
//		 	            }
//		 	            return null;
//		 	        }
//		 	        return null;
//		 	    	 
		 	 
//	}
     
	
	
}
