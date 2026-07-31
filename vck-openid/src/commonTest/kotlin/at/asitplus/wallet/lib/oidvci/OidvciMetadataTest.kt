package at.asitplus.wallet.lib.oidvci

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.mdl.MDL_DOCTYPE
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.nulls.shouldNotBeNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

val OidvciMetadataTest by matrixSuite {

    fixture {
        object {
            val authorizationService = SimpleAuthorizationService(
                strategy = CredentialAuthorizationServiceStrategy(AttributeIndex.schemeSet),
            )
            val issuer = CredentialIssuer(
                authorizationService = authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = AttributeIndex.schemeSet,
            )
        }
    } - {
        test("metadata for ISO_MDOC") {
            joseCompliantSerializer.encodeToJsonElement(it.issuer.metadata).jsonObject.apply {
                get("credential_configurations_supported").shouldNotBeNull().jsonObject.apply {
                    get(MDL_DOCTYPE).shouldNotBeNull().jsonObject.apply {
                        get("credential_signing_alg_values_supported").shouldNotBeNull().jsonArray.apply {
                            shouldHaveSingleElement(JsonPrimitive(-9))
                        }
                    }
                }
            }
        }
    }
}
