package com.tzl.backend.config;

import com.tzl.backend.Entity.RestBean;
import com.tzl.backend.Entity.vo.response.AuthorizeVO;
import com.tzl.backend.Utils.JwtUtils;
import com.tzl.backend.filter.JwtAuthorizeFilter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.io.PrintWriter;


@Configuration
public class SecurityConfiguration {

    @Autowired
    JwtUtils utils;

    @Autowired
    JwtAuthorizeFilter filter;



    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(conf -> conf
                        .requestMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
//                .formLogin(AbstractHttpConfigurer::disable)
//                .logout(AbstractHttpConfigurer::disable)
               .formLogin(conf -> conf
                        .loginProcessingUrl("/api/auth/login")
                        .loginPage("/api/auth/login")
                        .successHandler(this::onAuthenticationSuccess)
                        .failureHandler(this::onAuthenticationFailure)
                )
                .logout(conf -> conf
                        .logoutUrl("/api/auth/logout")
                        .logoutSuccessHandler(this::onLogoutSuccess)
                )
                .exceptionHandling(conf -> conf
                        .authenticationEntryPoint(this::onUnAuthorized)
                        .accessDeniedHandler(this::onAccessDeny)
                )
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(conf -> conf
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
                .build();


    }

    public void onAccessDeny(HttpServletRequest request,
                             HttpServletResponse response,
                             AccessDeniedException e) throws IOException {
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(RestBean.forbidden(e.getMessage()).asJsonString());

    }

    public void onUnAuthorized(HttpServletRequest request,
                               HttpServletResponse response,
                               AuthenticationException e) throws IOException {
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(RestBean.unAuthorized(e.getMessage()).asJsonString());

    }


    private void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        User user = (User) authentication.getPrincipal();
        String token = utils.createJwt(user,1,"小明");
        AuthorizeVO vo = new AuthorizeVO();
        vo.setExpire(utils.expireTime());
        vo.setRole("");
        vo.setToken(token);
        vo.setUsername("小明");
        response.getWriter().write(RestBean.success(vo).asJsonString());
    }

    private void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException e) throws IOException {
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(RestBean.unAuthorized(e.getMessage()).asJsonString());
    }

    private void onLogoutSuccess(HttpServletRequest request,
                                 HttpServletResponse response,
                                 Authentication authentication) throws IOException {
        response.setContentType("application/json;charset=utf-8");
        PrintWriter writer = response.getWriter();
        String authorization = request.getHeader("Authorization");
        if(utils.invalidateJwt(authorization)){
            writer.write(RestBean.success().asJsonString());
        }else{
            writer.write(RestBean.failure(400,"退出登录失败！").asJsonString());
        }
    }


}
