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
package org.springframework.security.config.annotation.web.configurers.oauth2.client

import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.core.user.OAuth2User

/**
 * test for OAuth2LoginConfigurer.
 * @author Kazuki Shimizu
 * @since 5.0
 */
class OAuth2LoginConfigurerTests extends BaseSpringSpec {

	def "oauth2Login logout"() {
		setup:
			OAuth2User user = Mock(OAuth2User)
			1 * user.getName() >> "foo"
			OAuth2LoginConfig.repository = Mock(ClientRegistrationRepository)
			OAuth2LoginConfig.service = Mock(OAuth2AuthorizedClientService)
			OAuth2LoginConfig.useAuthorizedClientServiceLogoutHander = true
			loadConfig(OAuth2LoginConfig)
			login(new OAuth2AuthenticationToken(user, Collections.emptyList(), "google"))
		when:
			request.method = "POST"
			request.servletPath = "/logout"
			springSecurityFilterChain.doFilter(request, response, chain)
		then:
			1 * OAuth2LoginConfig.service.removeAuthorizedClient("google", "foo")
	}

	def "oauth2Login logout with disableAuthorizedClientLogoutHandler"() {
		setup:
			OAuth2User user = Mock(OAuth2User)
			OAuth2LoginConfig.repository = Mock(ClientRegistrationRepository)
			OAuth2LoginConfig.service = Mock(OAuth2AuthorizedClientService)
			OAuth2LoginConfig.useAuthorizedClientServiceLogoutHander = false
			loadConfig(OAuth2LoginConfig)
			login(new OAuth2AuthenticationToken(user, Collections.emptyList(), "google"))
		when:
			request.method = "POST"
			request.servletPath = "/logout"
			springSecurityFilterChain.doFilter(request, response, chain)
		then:
			0 * OAuth2LoginConfig.service.removeAuthorizedClient("google", "foo")
	}

	@EnableWebSecurity
	static class OAuth2LoginConfig extends WebSecurityConfigurerAdapter {
		static OAuth2AuthorizedClientService service
		static ClientRegistrationRepository repository
		static boolean useAuthorizedClientServiceLogoutHander

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.oauth2Login()
					.clientRegistrationRepository(repository)
					.authorizedClientService(service)
			if (!useAuthorizedClientServiceLogoutHander) {
				http.oauth2Login().disableAuthorizedClientLogoutHandler()
			}
		}
	}

}
