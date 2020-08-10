package com.cos.jwtex01.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwtex01.config.auth.PrincipalDetails;
import com.cos.jwtex01.dto.LoginRequestDto;
import com.cos.jwtex01.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

//인증
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
   
	
	private final AuthenticationManager authenticationManager;

	// Authentication 객체 만들어서 리턴 =>의존 :AuthenticationManager
	// 인증 요청시에 실행되는 함수 => /login일때 만 
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		// request 에 있는 username과 password를 파싱해서 자바 Object로 받기
        System.out.println("JwtAuthenticationFilter : 진입");
		
		ObjectMapper om = new ObjectMapper();
		LoginRequestDto loginRequestDto = null;
		try {
			loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);
		} catch (Exception e) {
			// TODO: handle exception
		}
         
		System.out.println("JwtAuthenticationFilter : "+loginRequestDto);
		
		// 유저네임패스워드 토큰 생성
		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
				loginRequestDto.getUsername(), 
				loginRequestDto.getPassword());
		System.out.println("JwtAuthenticationFilter : 토큰생성완료");
		//Authenticate() 함수가 호출 되면 인증 provider가 유저 디테일 서비스의 
		
		//loadUserByUsername(토큰의 첫번째 파라미터)를 호출 하고 
		//UserDetails를 리턴받아서 토큰의 두번째 파라미터(credential)과 
		//UserDetails(Db값)의 getPasssword()함수로 비교해서 동일하면 
		//Authentication 객체를 만들어서 필터체인으로 리턴해준다. 
		
		//Tip:인증 provider의 디폴트 서비스는 UserDetailsService타입 
		//Tip:인증 provider의 디폴트 암호화 방식은 BCryPasswordEncoder
		//결론은 인증 provider에게 알려줄 필요가 없다.
		
		
		Authentication authentication = authenticationManager.authenticate(authenticationToken);
		
         System.out.println("Authentication :" + authentication.getCredentials());
		PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
		System.out.println("Authentication: "+ principalDetails.getUsername());
		System.out.println("Authentication: "+ principalDetails.getUser());
		
		return authentication;

	}

	// JWT Token 생성해서 응답해주기 (response에 정보를 header에 담아주기)
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		PrincipalDetails principalDetails = (PrincipalDetails)authResult.getPrincipal();
		
		String jwtToken = JWT.create()
				.withSubject(principalDetails.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512(JwtProperties.SECRET));
		
		response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+ jwtToken);		
//		Cookie cookie = new Cookie("Authorization",jwtToken);
//		response.addCookie(cookie);
	}

}
