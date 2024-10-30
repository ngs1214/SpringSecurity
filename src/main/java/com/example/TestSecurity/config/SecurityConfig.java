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
    //암호화 메서드 추가
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        //스프링부트 3.1 ~ , 스프링 6.1 ~ 부터는 필수적으로 람다표현식으로 처리
        http
                .authorizeHttpRequests(auth -> auth
                        //permitAll(): 모든 사용자 접근, hasRole(): 특정 규칙이 부합한 사용자만 접근
                        //authenticated(): 로그인된 유저 다 허용, denyAll(): 모든 사용자 접근 불가
                        //해당 경로 인가는 상단부터 적용되니 순서 중요
                        .requestMatchers("/", "/login", "/loginProc","/join","/joinProc").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
                        .anyRequest().authenticated()
                );
        //개발환경에서 csrf설정 해제
        //요청을 위조하여 사용자가 원하지 않아도 서버측으로 요청을 해서 강제로 변경
        //사용하면(기본값 사용) CsrfFilter를 통해서 토큰검증을 진행함
        //예제로그인시에 해당 토큰도 같이 넘겨줘야함
        //api서버 같은 경우는 필요없음
//        http
//                .csrf(auth -> auth.disable());


        http
                .formLogin(auth -> auth.loginPage("/login")
                        .loginProcessingUrl("/loginProc").permitAll()
                );
        http
                .logout((auth) -> auth.logoutUrl("/logout")
                        .logoutSuccessUrl("/"));
        http
                .sessionManagement((auth) -> auth
                        //하나의 아이디 동시접속 개수
                        .maximumSessions(1)
                        //위에 갯수를 초과하는 다중로그인시 기존 로그인처리 방법
                        //true : 초과시 새로운 로그인 차단
                        //false : 초과시 기존 세션 하나 삭제
                        .maxSessionsPreventsLogin(true)
                );

        http
                .sessionManagement((auth) -> auth
                        //세션 고정관련
                        //해커가 세션을 탈취하여 해킹함을 방지
                        //newSession() : 로그인시 세션 새로 생성
                        //changeSessionId() : 로그인시 동일한 세션에 대한 id변경
                        .sessionFixation().changeSessionId()
                );
        return http.build();

    }
}
