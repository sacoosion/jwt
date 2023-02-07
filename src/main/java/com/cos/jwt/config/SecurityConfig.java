package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.filter.CorsFilter;

import com.cos.jwt.config.auth.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.auth.jwt.JwtAuthorizationFilter;
import com.cos.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	private final CorsFilter corsFilter;
	private final UserRepository userRepository;
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
		//http.addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class);
		//http.addFilterAfter(new MyFilter3(), BasicAuthenticationFilter.class);
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // STATELESS방식을 사용하겠다 = 세션을 사용하지 않겠다.
			.and()
			.addFilter(corsFilter) //@CrossOrigin (인증 없을때), 인증 있을때는 시큐리티 필터에 등록을 해줘야한다.
			.formLogin().disable()
			.httpBasic().disable() // 기본인증방식(ID와PW를 가져가는 방식) 안씀
			.addFilter(new JwtAuthenticationFilter(authenticationManager())) //AuthenticationManager
			.addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository)) //AuthenticationManager
			.authorizeRequests()
			.antMatchers("/api/v1/user/**")
			.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
			.antMatchers("/api/v1/manager/**")
			.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
			.antMatchers("api/v1/admin/**")
			.access("hasRole('ROLE_ADMIN')")
			.anyRequest().permitAll();
	}

}
