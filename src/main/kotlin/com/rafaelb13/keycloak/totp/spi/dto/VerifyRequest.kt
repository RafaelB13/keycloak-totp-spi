package com.rafaelb13.keycloak.totp.spi.dto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.annotation.JsonSerialize

@JsonSerialize
data class VerifyRequest(
    @JsonProperty("deviceName")
    val deviceName: String? = null,

    @JsonProperty("code")
    val code: String
) {
    companion object {
        fun validate(request: VerifyRequest): Boolean {
            return request.code.isNotEmpty()
        }
    }
}