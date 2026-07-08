package at.asitplus.wallet.lib.iso

import at.asitplus.iso.DeviceRequest
import at.asitplus.wallet.lib.RequestOptions

@Deprecated("Use OpenId4VpRequestOptions and DcApiVerifier instead")
data class Iso180137AnnexCRequestOptions(
    /**
     * Device request can be built using [CredentialPresentationRequestBuilder]
     */
    val deviceRequest: DeviceRequest,
    /** Transaction ID. */
    override val state: String,
) : RequestOptions