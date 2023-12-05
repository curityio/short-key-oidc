/*
 * Copyright 2023 Curity AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.curity.identityserver.plugins.authenticator.authentication

import se.curity.identityserver.sdk.errors.ErrorCode.INVALID_REDIRECT_URI
import se.curity.identityserver.sdk.service.ExceptionFactory
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider

import java.net.MalformedURLException
import java.net.URL

import io.curity.identityserver.plugins.authenticator.descriptor.ShortKeyOidcAuthenticatorPluginDescriptor.Companion.CALLBACK

class RedirectUriUtil
{
    private constructor()

    companion object {
        fun createRedirectUri(authenticatorInformationProvider: AuthenticatorInformationProvider,
        exceptionFactory: ExceptionFactory): String
        {
            try
            {
                val authUri = authenticatorInformationProvider.fullyQualifiedAuthenticationUri

                return URL(authUri.toURL(), authUri.path + "/" + CALLBACK).toString()
            }
            catch (e: MalformedURLException)
            {
                throw exceptionFactory.internalServerException(INVALID_REDIRECT_URI,
                    "Could not create redirect URI")
            }
        }
    }
}
