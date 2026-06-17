package at.asitplus.wallet.lib.data

import at.asitplus.dif.Constraint
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.ConstraintFilter
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.InMemorySubjectCredentialStore
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.dif.PresentationExchangeInputEvaluator
import at.asitplus.wallet.lib.data.rfc3986.toUri
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put

/**
 * A scalar `$.type` filter (see [at.asitplus.wallet.lib.RequestOptions]) must match VC-JWT credentials whose `type` is
 * an array — both legacy store entries (serialized before [SubjectCredentialStore.StoreEntry.schemeIdentifier] existed,
 * so the full `type` array is exposed) and any VC carrying multiple types.
 */
val LegacyVcTypeConstraintTest by matrixSuite {

    fun typeConstraint(type: String) = Constraint(
        fields = setOf(
            ConstraintField(
                path = listOf("$.type"),
                filter = ConstraintFilter(type = "string", const = JsonPrimitive(type)),
            )
        )
    )

    "scalar type filter matches an entry of the VC type array" {
        val credential = buildJsonObject {
            put("type", JsonArray(listOf(JsonPrimitive("VerifiableCredential"), JsonPrimitive("AtomicAttribute2023"))))
        }
        PresentationExchangeInputEvaluator
            .evaluateInputDescriptorConstraint(typeConstraint("AtomicAttribute2023"), credential) { true }
            .isSuccess shouldBe true
    }

    "scalar type filter does not match a type absent from the array" {
        val credential = buildJsonObject {
            put("type", JsonArray(listOf(JsonPrimitive("VerifiableCredential"), JsonPrimitive("AtomicAttribute2023"))))
        }
        PresentationExchangeInputEvaluator
            .evaluateInputDescriptorConstraint(typeConstraint("SomeOtherCredential"), credential) { true }
            .isSuccess shouldBe false
    }

    // The array relaxation must stay scoped to the VC `type` field: a scalar constraint on another field must not be
    // silently satisfied by an array value (see PR #571 review).
    "scalar filter on a non-type field is not satisfied by an array value" {
        val statusConstraint = Constraint(
            fields = setOf(
                ConstraintField(
                    path = listOf("$.status"),
                    filter = ConstraintFilter(type = "string", const = JsonPrimitive("active")),
                )
            )
        )
        val credential = buildJsonObject {
            put("status", JsonArray(listOf(JsonPrimitive("active"), JsonPrimitive("revoked"))))
        }
        PresentationExchangeInputEvaluator
            .evaluateInputDescriptorConstraint(statusConstraint, credential) { true }
            .isSuccess shouldBe false
    }

    "legacy VC entry without scheme identifier matches the VC type constraint" {
        val holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
        val issuer = IssuerAgent(
            keyMaterial = EphemeralKeyWithSelfSignedCert(),
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default,
        )
        val holder = HolderAgent(holderKeyMaterial, InMemorySubjectCredentialStore())
        holder.storeCredential(
            issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(holderKeyMaterial.publicKey, AtomicAttribute2023, PLAIN_JWT)
                    .getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        ).getOrThrow()
        val legacyEntry = holder.getCredentials()!!
            .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
            .single()
            .copy(schemeIdentifier = null) // simulate an entry serialized before scheme-identifier existed

        val json = CredentialToJsonConverter.toJsonElement(legacyEntry).jsonObject
        // The full type array is exposed; the scalar filter matches an entry of it.
        json["type"].shouldBeInstanceOf<JsonArray>() shouldContain JsonPrimitive(AtomicAttribute2023.vcType)
        PresentationExchangeInputEvaluator
            .evaluateInputDescriptorConstraint(typeConstraint(AtomicAttribute2023.vcType), json) { true }
            .isSuccess shouldBe true
    }
}
