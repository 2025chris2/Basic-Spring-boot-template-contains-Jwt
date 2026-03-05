package com.tzl.backend.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.tzl.backend.Utils.JwtUtils;
import jakarta.annotation.Resource;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthorizeFilter extends OncePerRequestFilter {

    @Resource
    JwtUtils utils;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        try {
            String authorization = request.getHeader("Authorization");
            // 如果没头，直接跳过，不设置认证，让 Spring Security 报 401
            if (authorization != null && authorization.startsWith("Bearer ")) {
                DecodedJWT jwt = utils.resolveJwt(authorization);
                if (jwt != null) {
                    UserDetails user = utils.toUser(jwt);
                    // 确保 user 不为 null
                    if (user != null) {
                        UsernamePasswordAuthenticationToken authentication =
                                new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                        request.setAttribute("id", utils.toId(jwt));
                    }
                }
            }
        } catch (Exception e) {
            // 记录日志，但不要抛出，避免中断请求链，让后续 Spring Security 处理 401
            e.printStackTrace();
        }

        filterChain.doFilter(request, response);
    }
}
