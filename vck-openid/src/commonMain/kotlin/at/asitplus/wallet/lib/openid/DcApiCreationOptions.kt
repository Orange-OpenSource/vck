package at.asitplus.wallet.lib.openid

/**
 * Options for creating requests for the W3C Digital Credentials API in [DcApiVerifier.createAuthnRequest],
 * reflecting the exchange protocols available over that API,
 * see [at.asitplus.dcapi.request.ExchangeProtocolIdentifier].
 */
sealed class DcApiCreationOptions {

    /**
     * Unsigned OpenID4VP 1.0 request, i.e. protocol `openid4vp-v1-unsigned`,
     * see [at.asitplus.dcapi.request.verifier.DigitalCredentialGetRequest.OpenId4VpUnsigned].
     */
    data object OpenId4VpUnsigned : DcApiCreationOptions()

    /**
     * Signed OpenID4VP 1.0 request, i.e. protocol `openid4vp-v1-signed`,
     * see [at.asitplus.dcapi.request.verifier.DigitalCredentialGetRequest.OpenId4VpSigned].
     */
    data object OpenId4VpSigned : DcApiCreationOptions()

    // TODO: OpenId4VpMultiSigned (`openid4vp-v1-multisigned`) and Iso18013AnnexC (`org-iso-mdoc`)
}
