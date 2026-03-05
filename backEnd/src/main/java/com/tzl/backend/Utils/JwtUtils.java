package com.tzl.backend.Utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.TimeUnit;

@Component
public class JwtUtils {

    @Value("${spring.security.jwt.key}")
    String key;

    @Value("${spring.security.jwt.expire}")
    int expire;

    @Autowired
    StringRedisTemplate template;

    public boolean invalidateJwt(String headerToken){
        String token = convertToken(headerToken);
        if(token == null) return false;
        Algorithm algorithm = Algorithm.HMAC256(key);
        JWTVerifier verifier = JWT.require(algorithm).build();
        try {
            DecodedJWT jwt = verifier.verify(token);
            String id = jwt.getId();
            return deleteToken(id,jwt.getExpiresAt());
        } catch (JWTVerificationException e) {
            return false;
        }
    }

    private boolean deleteToken(String uuid, Date time){
        if(this.isInvalidToken(uuid)) return false;
        long ttl = time.getTime() - System.currentTimeMillis();
        if (ttl > 0) {
            template.opsForValue().set(Const.JWT_BLACK_LIST + uuid, "",expire, TimeUnit.MILLISECONDS);
        }
        return true;
    }

    private boolean isInvalidToken(String uuid){
        return template.hasKey(Const.JWT_BLACK_LIST + uuid);
    }


    public UserDetails toUser(DecodedJWT jwt){
        Map<String, Claim> claims = jwt.getClaims();
        // 获取权限列表，注意 Claim 转 List 的方式取决于你的 JWT 库，这里假设是 List<String>
        List<String> roles = claims.get("authorities").asList(String.class);

        List<GrantedAuthority> authorities = new ArrayList<>();
        if (roles != null) {
            for (String role : roles) {
                authorities.add(new SimpleGrantedAuthority(role));
            }
        }
        return User
                .withUsername(claims.get("username").asString()) // 使用 asString() 更安全
                .password("******")
                .authorities(authorities) // 传入对象集合
                .build();
    }

    public Integer toId(DecodedJWT jwt){
        Map<String, Claim> claims = jwt.getClaims();
        return claims.get("id").asInt();
    }

    public DecodedJWT resolveJwt(String headerToken){
        String token = convertToken(headerToken);
        if(token == null) return null;
        Algorithm algorithm = Algorithm.HMAC256(key);
        JWTVerifier verifier = JWT.require(algorithm).build();
        try {
            DecodedJWT jwt = verifier.verify(token);
            if(this.isInvalidToken(jwt.getId())) return null;
            Date date = jwt.getExpiresAt();
            return new Date().after(date) ? null : jwt;
        } catch (JWTVerificationException e) {
            return null;
        }

    }

    public String convertToken(String headerToken){
        if(headerToken == null || !headerToken.startsWith("Bearer")) return null;
        return headerToken.substring(7);
    }

    public String createJwt(UserDetails details,int id,String username){
        Algorithm algorithm = Algorithm.HMAC256(key);
        Date expire = expireTime();
        return JWT.create()
                .withJWTId(UUID.randomUUID().toString())
                .withClaim("id",id)
                .withClaim("username", username)
                .withClaim("authorities",details.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withExpiresAt(expire)
                .withIssuedAt(new Date())
                .sign(algorithm);
    }

    public Date expireTime(){
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR,expire);
        return calendar.getTime();
    }
}
