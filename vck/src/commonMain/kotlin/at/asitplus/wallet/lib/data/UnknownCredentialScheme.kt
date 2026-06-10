package at.asitplus.wallet.lib.data

data class UnknownCredentialScheme(val representation: CredentialRepresentation) : CredentialScheme {
    override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/unknown.json"
    override val supportedRepresentations: Collection<CredentialRepresentation> = listOf(representation)
}