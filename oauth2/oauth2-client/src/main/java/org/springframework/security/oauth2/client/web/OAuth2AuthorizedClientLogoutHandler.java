/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.Assert;

/**
 * {@link OAuth2AuthorizedClientLogoutHandler} is in charge of removing the
 * {@link org.springframework.security.oauth2.client.OAuth2AuthorizedClient} upon logout.
 *
 * @author Kazuki Shimizu
 * @since 5.0
 */
public class OAuth2AuthorizedClientLogoutHandler implements LogoutHandler {

	private final OAuth2AuthorizedClientService authorizedClientService;

	/**
	 * Creates a new instance.
	 * @param authorizedClientService the {@link OAuth2AuthorizedClientService} to use
	 */
	public OAuth2AuthorizedClientLogoutHandler(
			OAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.authorizedClientService = authorizedClientService;
	}

	/**
	 * Clears the
	 * {@link org.springframework.security.oauth2.client.OAuth2AuthorizedClient}.
	 *
	 * @see org.springframework.security.web.authentication.logout.LogoutHandler#logout(javax.servlet.http.HttpServletRequest,
	 * javax.servlet.http.HttpServletResponse,
	 * org.springframework.security.core.Authentication)
	 */
	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) {
		if (authentication instanceof OAuth2AuthenticationToken) {
			OAuth2AuthenticationToken oauth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
			this.authorizedClientService.removeAuthorizedClient(
					oauth2AuthenticationToken.getAuthorizedClientRegistrationId(),
					oauth2AuthenticationToken.getPrincipal().getName());
		}
	}

}
