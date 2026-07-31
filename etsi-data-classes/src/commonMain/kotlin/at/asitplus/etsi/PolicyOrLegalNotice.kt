package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class PolicyOrLegalNotice(
    private val list: List<PolicyOrLegalNoticeItem>,
) : List<PolicyOrLegalNoticeItem> by list {
    constructor(vararg elements: PolicyOrLegalNoticeItem): this(elements.toList())
}