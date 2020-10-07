package com.example.demo;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

public class CsrfCookieFilter extends OncePerRequestFilter {
	private static final String CSRF_COOKIE_NAME = "_ctkn";
	private static final String CSRF_COOKIE_PATH = "/";

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class
				.getName());

		if (csrf != null) {
			final String token = csrf.getToken();
			Cookie cookie = WebUtils.getCookie(request, CSRF_COOKIE_NAME);
			if (cookie == null || token != null
					&& !token.equals(cookie.getValue())) {
				cookie = new Cookie(CSRF_COOKIE_NAME, token);
				cookie.setPath(CSRF_COOKIE_PATH);
				response.addCookie(cookie);
			}
		}

		filterChain.doFilter(request, response);
	}
}
