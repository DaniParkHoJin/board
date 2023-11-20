package org.parkhojin.configs;

import jakarta.servlet.http.HttpServletResponse;
import org.parkhojin.medels.member.LoginFailureHandler;
import org.parkhojin.medels.member.LoginSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableConfigurationProperties(FileUploadConfig.class)
public class SecurityConfig {

    @Autowired
    private FileUploadConfig fileUploadConfig;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.formLogin(f -> {
            f.loginPage("/member/login")
                    .usernameParameter("email")
                    .passwordParameter("password")
                    .successHandler(new LoginSuccessHandler())
                    .failureHandler(new LoginFailureHandler());
        }); // DSL

        http.logout(c -> {
            c.logoutRequestMatcher(new AntPathRequestMatcher("/member/logout"))
                    .logoutSuccessUrl("/member/login");
        });

        http.headers(c -> {
            c.frameOptions(o -> o.sameOrigin());
        });
        http.authorizeHttpRequests(c -> {
            c.requestMatchers("/mypage/**").authenticated() // 회원 전용 페이지
                    .requestMatchers("/admin/**").hasAuthority("ADMIN") // 관리자 권한만 접근
                    .anyRequest().permitAll(); // 나머지 페이지는 권한 필요 없음
        });

        http.exceptionHandling(c-> {
            c.authenticationEntryPoint((req, resp, e)->{
               String URI = req.getRequestURI();
                if (URI.indexOf("/admin") != -1) { // 관리자 페이지 401 응답코드
                    resp.sendError(HttpServletResponse.SC_UNAUTHORIZED,"NOT AUTHORIZED");
                } else {
                    String url = req.getContextPath() + "/member/login";
                    resp.sendRedirect(url);
                }
            });
        });

        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return w -> w.ignoring().requestMatchers("/front/css/**", "front/js/**", "front/images/**", "/mobile/css/**", "/mobile/js/**", "/mobile/images/**", "/admin/css/**", "/admin/js/**", "/admin/images/**", "/common/css/**", "/common/js/**", "/common/images/**",
                fileUploadConfig.getUrl() + "**");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
