package com.rafaelb13.keycloak.totp.spi.dto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.annotation.JsonSerialize


@JsonSerialize
data class GenerateResponse(
    @JsonProperty("encodedSecret")
    val encodedSecret: String,

    @JsonProperty("qrCode")
    val qrCode: String
)