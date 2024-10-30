package com.example.TestSecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        //스프링부트 3.1 ~ , 스프링 6.1 ~ 부터는 필수적으로 람다표현식으로 처리
        http
                .authorizeHttpRequests(auth -> auth
                        //permitAll(): 모든 사용자 접근, hasRole(): 특정 규칙이 부합한 사용자만 접근
                        //authenticated(): 로그인된 유저 다 허용, denyAll(): 모든 사용자 접근 불가
                        //해당 경로 인가는 상단부터 적용되니 순서 중요
                        .requestMatchers("/", "/login").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
                        .anyRequest().authenticated()
                );
        //개발환경에서 csrf설정 해제
        http
                .csrf(auth -> auth.disable());

        http
                .formLogin(auth -> auth.loginPage("/login")
                        .loginProcessingUrl("/loginProc").permitAll()
                );

        return http.build();

    }
}
