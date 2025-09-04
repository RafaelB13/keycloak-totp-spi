package com.rafaelb13.keycloak.totp.spi

import com.rafaelb13.keycloak.totp.spi.api.TotpResource
import org.keycloak.models.KeycloakSession
import org.keycloak.services.resource.RealmResourceProvider

class TotpResourceProvider(
    private val session: KeycloakSession
): RealmResourceProvider {
    override fun close() {}

    override fun getResource(): TotpResource {
        return TotpResource(session)
    }
}