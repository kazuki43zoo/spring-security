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

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import java.util.Collections;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * The tests for {@link OAuth2AuthorizedClientLogoutHandler}.
 * @author Kazuki Shimizu
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2AuthorizedClientLogoutHandlerTests {

	@Mock
	private OAuth2AuthorizedClientService authorizedClientService;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private OAuth2AuthorizedClientLogoutHandler handler;

	@Before
	public void setup() {
		request = new MockHttpServletRequest();
		response = new MockHttpServletResponse();
		handler = new OAuth2AuthorizedClientLogoutHandler(authorizedClientService);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullOAuth2AuthorizedClientService() {
		new OAuth2AuthorizedClientLogoutHandler(null);
	}

	@Test
	public void removesAuthorizedClient() {

		String clientRegistrationId = "google";
		String principalName = "foo";
		OAuth2User user = mock(OAuth2User.class);
		when(user.getName()).thenReturn(principalName);
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(user,
				Collections.emptyList(), clientRegistrationId);

		handler.logout(request, response, token);

		verify(authorizedClientService).removeAuthorizedClient(clientRegistrationId,
				principalName);

	}

	@Test
	public void notRemovesAuthorizedClientWhenAuthenticationIsNotOAuth2AuthenticationToken() {

		handler.logout(request, response,
				new TestingAuthenticationToken("foo", "password", "ROLE_USER"));

		verifyZeroInteractions(authorizedClientService);

	}

}
