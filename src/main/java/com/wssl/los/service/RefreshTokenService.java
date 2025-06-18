package com.wssl.los.service;

import java.time.LocalDateTime;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.wssl.los.model.RefreshToken;
import com.wssl.los.repository.RefreshTokenRepository;
import com.wssl.los.util.JwtUtil;

@Service
public class RefreshTokenService {

	@Autowired
	private RefreshTokenRepository refreshTokenRepository;

	@Autowired
	private JwtUtil jwtUtil;

	public RefreshToken saveRefreshToken(String username, String token) {
		RefreshToken refreshToken = new RefreshToken();
		refreshToken.setToken(token);
		refreshToken.setUsername(username);
		refreshToken.setExpiryDate(LocalDateTime.now().plusSeconds(jwtUtil.getRefreshTokenExpirationMs() / 1000));
		refreshToken.setDelflg("N");
		return refreshTokenRepository.save(refreshToken);
	}

	public Optional<RefreshToken> findByToken(String token) {
		return refreshTokenRepository.findByToken(token);
	}

	public boolean isRefreshTokenValid(String token) {
		Optional<RefreshToken> refreshTokenOpt = findByToken(token);
		if (refreshTokenOpt.isPresent()) {
			RefreshToken refreshToken = refreshTokenOpt.get();
			return "N".equalsIgnoreCase(refreshToken.getDelflg())
					&& refreshToken.getExpiryDate().isAfter(LocalDateTime.now()) && jwtUtil.validateToken(token);
		}
		return false;
	}

	public void deleteRefreshToken(String token) {
		refreshTokenRepository.findByToken(token).ifPresent(tokenEntity -> {
			tokenEntity.setDelflg("Y");
			refreshTokenRepository.save(tokenEntity);
		});
	}

	public void deleteByUsername(String username) {
		refreshTokenRepository.deleteByUsername(username);
	}
}