package at.asitplus.wallet.lib.agent

import at.asitplus.dif.Constraint
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment.NameSegment
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.rfc3986.toUri
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

/**
 * Regression test: ISO mdoc store entries serialized before [SubjectCredentialStore.StoreEntry.schemeIdentifier]
 * existed keep that field `null`. Input-descriptor matching must still derive the docType from `issuerAuth` so that
 * `MSO_MDOC` input descriptors keyed by docType continue to match those legacy entries.
 */
val LegacyIsoSchemeMatchingTest by matrixSuite {

    suspend fun legacyIsoEntryWithoutSchemeIdentifier(): SubjectCredentialStore.StoreEntry.Iso {
        val holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
        val issuer = IssuerAgent(
            keyMaterial = EphemeralKeyWithSelfSignedCert(),
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default,
        )
        val issued = issuer.issueCredential(
            DummyCredentialDataProvider.getCredential(holderKeyMaterial.publicKey, AtomicAttribute2023, ISO_MDOC)
                .getOrThrow()
        ).getOrThrow().shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()

        @Suppress("DEPRECATION")
        return SubjectCredentialStore.StoreEntry.Iso(
            issuerSigned = issued.issuerSigned,
            schemaUri = AtomicAttribute2023.schemaUri,
            schemeIdentifier = null, // entry serialized before scheme-identifier was introduced
        )
    }

    fun isoInputDescriptor(id: String) = DifInputDescriptor(
        id = id,
        constraints = Constraint(
            fields = setOf(
                ConstraintField(
                    path = listOf(
                        NormalizedJsonPath(
                            NameSegment(AtomicAttribute2023.isoNamespace),
                            NameSegment(CLAIM_GIVEN_NAME),
                        ).toString()
                    )
                )
            )
        )
    )

    "legacy ISO entry without scheme identifier matches its docType input descriptor" {
        val holder = HolderAgent(EphemeralKeyWithSelfSignedCert(), InMemorySubjectCredentialStore())
        val entry = legacyIsoEntryWithoutSchemeIdentifier()

        holder.evaluateInputDescriptorAgainstCredential(
            inputDescriptor = isoInputDescriptor(AtomicAttribute2023.isoDocType),
            credential = entry,
            fallbackFormatHolder = null,
        ) { true }.isSuccess shouldBe true
    }

    "legacy ISO entry without scheme identifier is rejected for a mismatched docType" {
        val holder = HolderAgent(EphemeralKeyWithSelfSignedCert(), InMemorySubjectCredentialStore())
        val entry = legacyIsoEntryWithoutSchemeIdentifier()

        holder.evaluateInputDescriptorAgainstCredential(
            inputDescriptor = isoInputDescriptor("org.example.other.doctype"),
            credential = entry,
            fallbackFormatHolder = null,
        ) { true }.isSuccess shouldBe false
    }
}
