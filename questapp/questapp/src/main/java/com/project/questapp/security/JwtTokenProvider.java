package com.project.questapp.security;


import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;

@Component
public class JwtTokenProvider {
	
	// application.properties içinde tanımlayacak
	
	
	@Value("${questapp.app.secret}")
	private String APP_SECRET; // key oluştururken kullanılacak
	
	@Value("${questapp.app.expires.in}")
	private long EXPIRES_IN; // keyin kaç sn kullanılacağını belirleyecek
	
	public String generateJwtToken(Authentication  auth) {
		JwtUserDetails userDetails = (JwtUserDetails) auth.getPrincipal();
		Date expireDate = new Date(new Date().getTime()+EXPIRES_IN);
		return Jwts.builder().setSubject(Long.toString(userDetails.getId()))
				.setIssuedAt(new Date()).setExpiration(expireDate)
				.signWith(SignatureAlgorithm.HS512,APP_SECRET).compact();
	}
	
	public String generateJwtTokenByUserId(Long userId) {
		Date expireDate = new Date(new Date().getTime() + EXPIRES_IN);
		return Jwts.builder().setSubject(Long.toString(userId))
				.setIssuedAt(new Date()).setExpiration(expireDate)
				.signWith(SignatureAlgorithm.HS512, APP_SECRET).compact();
	}
	
	Long getUserIdFromJwt(String token) {
		Claims claims = Jwts.parser().setSigningKey(APP_SECRET).build().parseClaimsJws(token).getBody();
		return Long.parseLong(claims.getSubject());
	}
	
	boolean validateToken(String token) {
		try {
			Jwts.parser().setSigningKey(APP_SECRET).build().parseClaimsJws(token);
			return !isTokenExpired(token);
		} catch (SignatureException e) {
			return false;
		}catch (MalformedJwtException e) {
			return false;
		}catch (ExpiredJwtException e) {
			return false;
		}catch (UnsupportedJwtException e) {
			return false;
		}catch (IllegalArgumentException e) {
			return false;
		}
	}

	private boolean isTokenExpired(String token) {
		Date expiration = Jwts.parser().setSigningKey(APP_SECRET).build().parseClaimsJws(token).getBody().getExpiration();
		return expiration.before(new Date());
	}
	
}
