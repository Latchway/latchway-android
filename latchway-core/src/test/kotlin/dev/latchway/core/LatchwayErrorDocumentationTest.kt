package dev.latchway.core

import org.junit.Assert.assertEquals
import org.junit.Test

public class LatchwayErrorDocumentationTest {
    @Test
    public fun everyPublicErrorCodeHasOneStableDocumentationPath(): Unit {
        LatchwayErrorCode.entries.forEach { code ->
            assertEquals(
                "https://docs.latchway.dev/errors/${code.wireValue}",
                code.documentationUrl.toASCIIString(),
            )
        }
    }

    @Test
    public fun exceptionExposesItsCodeDocumentationWithoutRenderingDetail(): Unit {
        val exception = LatchwayException(
            code = LatchwayErrorCode.QUOTA_EXCEEDED,
            requestId = "request-12345678",
            safeMessage = "quota unavailable",
        )

        assertEquals(
            "https://docs.latchway.dev/errors/quota_exceeded",
            exception.documentationUrl.toASCIIString(),
        )
        assertEquals("request-12345678", exception.requestId)
    }
}
