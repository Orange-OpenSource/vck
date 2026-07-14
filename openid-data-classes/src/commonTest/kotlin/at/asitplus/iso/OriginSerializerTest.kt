package at.asitplus.iso

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

val OriginSerializerTest by matrixSuite {

    test("host is serialized in lowercase") {
        "https://MacBook-Air.local:8443".serializeOrigin() shouldBe
                "https://macbook-air.local:8443"
    }
}
