package com.cos.jwt.config.auth.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음.
// /login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter가 동작함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;

	// /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");

		// 1. username, password 받아서
		try {
			/*
			 * BufferedReader br = request.getReader(); String input = null;
			 * while((input=br.readLine()) != null) { System.out.println(input); }
			 */
			// System.out.println(request.getInputStream().toString());
			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(), User.class);
			System.out.println(user);

			UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
					user.getUsername(), user.getPassword());

			// PrincipalDetailesService의 loadUserByUsername() 함수가 실행됨
			// 실행 후 정상이면 authentication이 리턴됨.
			// DB에 있는 username과 password가 일치한다.
			Authentication authentication = 
					authenticationManager.authenticate(authenticationToken);

			// authentication 객체가 session 영역에 저장됨 => 로그인이 되었다는 뜻
			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
			System.out.println("로그인 완료됨 : " + principalDetails.getUser().getUsername());
			// authentication 객체가 session 영역에 저장되어야 하고 그 방법이 return해주는 것이다.
			// 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는것
			// 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없지만 단지 권한 처리때문에 session에 넣어줌
			return authentication;
		} catch (IOException e) {
			e.printStackTrace();
		}

		System.out.println("========================================");
		// 2. 정상인지 로그인 시도를 해봄 authenticationManager로 로그인 시도를 하면!
		// PrincipalDetailsService가 호출됨
		// 자동으로 loadUserByUsername()함수가 실행됨.

		// 3. PrincipalDetails를 세션에 담고(권한관리를 위해) - 세션에 담지 않으면 권한관리를 할 수 없다.

		// 4. JWT토큰을 만들어서 응답해주면 됨.

		// return super.attemptAuthentication(request, response);
		return null; // 리턴값authentication은 try catch문 안에서 리턴, 오류나면 null리턴
	}

	// 뒤에 실행되는 함수가 있음
	// attemptAuthentication실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨
	// 여기서 JWT토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response해주면됨.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는뜻");
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
		
		// RSA 방식은 아니고 Hash암호방식
		String jwtToken = JWT.create()
				//.withSubject(principalDetails.getUsername()) // 크게 의미 없음
				.withSubject("cos토큰")
				//.withExpiresAt(new Date(System.currentTimeMillis()//현재시간 +JwtProperties.EXPIRATION_TIME))
				//.withExpiresAt(new Date(System.currentTimeMillis()+(60000*10)))
				.withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername()) //withClaim = 비공개Claim으로 넣고싶은 key=value값 막 넣으면 됨
				//.sign(Algorithm.HMAC512("cos")); // HMAC512는 secret값을 가지고 있어야함
				.sign(Algorithm.HMAC512(JwtProperties.SECRET)); //내 서버만 아는 고유한 값이어야함
		
		response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
		//response.addHeader("Authorization", "Bearer " + jwtToken);
		//super.successfulAuthentication(request, response, chain, authResult);
	}
}
