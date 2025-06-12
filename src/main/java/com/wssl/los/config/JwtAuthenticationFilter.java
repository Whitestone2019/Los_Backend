package com.wssl.los.config;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.wssl.los.util.JwtUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final JwtUtil jwtUtil;

	public JwtAuthenticationFilter(JwtUtil jwtUtil) {
		this.jwtUtil = jwtUtil;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		String header = request.getHeader("Authorization");
		String username = null;
		String token = null;

		if (header != null && header.startsWith("Bearer ")) {
			token = header.substring(7);
			if (jwtUtil.validateToken(token)) {
				username = jwtUtil.getUsernameFromToken(token);
			}
		}

		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, null);
			auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			SecurityContextHolder.getContext().setAuthentication(auth);
		}

		chain.doFilter(request, response);
	}
}