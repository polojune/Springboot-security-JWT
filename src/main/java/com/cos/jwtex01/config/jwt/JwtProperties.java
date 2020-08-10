package com.cos.jwtex01.config.jwt;

public interface JwtProperties {
   String SECRET="홍길동"; //비밀 값
   int EXPIRATION_TIME = 864000000;  //10일
   String TOKEN_PREFIX ="Bearer "; 
   String HEADER_STRING ="Authorization";
}
