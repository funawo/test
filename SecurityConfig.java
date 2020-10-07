package com.example.demo;

import javax.servlet.http.HttpServletRequest;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
	public void configure(HttpSecurity http) throws Exception {

		RequestMatcher csrfRequestMatcher = new RequestMatcher() {
			private AntPathRequestMatcher disabledRequestMatcher = new AntPathRequestMatcher("/login");

			@Override
			public boolean matches(HttpServletRequest request) {

				// ログインAPIは、CSRFチェックしない
				if (disabledRequestMatcher.matches(request)) {
					return false;
				}

				if ("GET".equals(request.getMethod())) {
					return false;
				}

				return true;
			}

		};

		http
				.authorizeRequests()
				.antMatchers("/**")
				.permitAll()
				.anyRequest()
				.authenticated()
				.and()
				.csrf()
				.requireCsrfProtectionMatcher(csrfRequestMatcher);

		// CSRFのチェック後(CsrfFilterの後)にCsrfCookieFilterを実行
		http.addFilterAfter(new CsrfCookieFilter(), CsrfFilter.class);

	}
}
