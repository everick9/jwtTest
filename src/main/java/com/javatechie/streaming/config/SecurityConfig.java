package com.javatechie.streaming.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.javatechie.streaming.jwt.JwtAccessDeniedHandler;
import com.javatechie.streaming.jwt.JwtAuthenticationEntryPoint;
import com.javatechie.streaming.jwt.JwtSecurityConfig;
import com.javatechie.streaming.jwt.TokenProvider;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
	private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    
    public SecurityConfig(
            TokenProvider tokenProvider,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		 http
	         .csrf().disable()
	
	         .exceptionHandling()
	         .authenticationEntryPoint(jwtAuthenticationEntryPoint)
	         .accessDeniedHandler(jwtAccessDeniedHandler)
	
	         .and()
	         .headers()
	         .frameOptions()
	         .sameOrigin()
	
	         .and()
	         .sessionManagement()
	         .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
	
	         .and()
	         .authorizeRequests()
	         .antMatchers("/api/hello").permitAll()
	         .antMatchers("/api/authenticate").permitAll()
	         .antMatchers("/api/signup").permitAll()
	         .anyRequest().authenticated()
	
	         .and()
	         .apply(new JwtSecurityConfig(tokenProvider));
		
		return http.build();
	}
	
	 @Bean
	    public WebSecurityCustomizer webSecurityCustomizer() {
		 	
	        /*return new WebSecurityCustomizer() {
				
				@Override
				public void customize(WebSecurity web) {
					web.ignoring().antMatchers("/h2-console/**","/favicon.ico");
					
				}
			};*/
		 
		 return (web) -> web.ignoring().antMatchers("/h2-console/**","/favicon.ico");
	    }
}
