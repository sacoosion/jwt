package com.cos.jwt.config.auth.jwt;

public interface JwtProperties {
	
	String SECRET = "cos"; // 우리 서버만 알고있는 비밀값
	int EXPIRATION_TIME = 60000*10; //10분 (단위 : 1/1000 초 : 60000=60초=1분)
	String TOKEN_PREFIX = "Bearer ";
	String HEADER_STRING = "Authorization";
}
