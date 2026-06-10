package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.IssuerSigned
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VcJwtCredentialScheme
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt

class InMemorySubjectCredentialStore : SubjectCredentialStore {

    private val credentials = mutableListOf<SubjectCredentialStore.StoreEntry>()

    override suspend fun storeCredential(
        vc: VerifiableCredentialJws,
        vcSerialized: String,
        scheme: VcJwtCredentialScheme,
        renewalInfo: CredentialRenewalInfo?,
    ) = SubjectCredentialStore.StoreEntry.Vc(
        vcSerialized = vcSerialized,
        vc = vc,
        schemaUri = scheme.schemaUri,
        renewalInfo = renewalInfo,
        schemeIdentifier = scheme.vcType,
    ).also { credentials += it }

    override suspend fun storeCredential(
        vc: VerifiableCredentialSdJwt,
        vcSerialized: String,
        disclosures: Map<String, SelectiveDisclosureItem?>,
        scheme: SdJwtCredentialScheme,
        renewalInfo: CredentialRenewalInfo?,
    ) = SubjectCredentialStore.StoreEntry.SdJwt(
        vcSerialized = vcSerialized,
        sdJwt = vc,
        disclosures = disclosures,
        schemaUri = scheme.schemaUri,
        renewalInfo = renewalInfo,
        schemeIdentifier = scheme.sdJwtType,
    ).also { credentials += it }

    override suspend fun storeCredential(
        issuerSigned: IssuerSigned,
        scheme: IsoMdocCredentialScheme,
        renewalInfo: CredentialRenewalInfo?,
    ) = SubjectCredentialStore.StoreEntry.Iso(
        issuerSigned = issuerSigned,
        schemaUri = scheme.schemaUri,
        renewalInfo = renewalInfo,
        schemeIdentifier = scheme.isoDocType,
    ).also { credentials += it }

    override suspend fun getCredentials(
        credentialSchemes: Collection<CredentialScheme>?,
    ): KmmResult<List<SubjectCredentialStore.StoreEntry>> = catching {
        credentialSchemes?.let { schemes ->
            credentials.filter { it.resolveScheme() in schemes }.toList()
        } ?: credentials
    }
}