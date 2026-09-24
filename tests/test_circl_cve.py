import httpx
import respx

from signalsage.intel.circl_cve import CIRCLCVEProvider
from signalsage.ioc.models import IOC, IOCType


@respx.mock
async def test_cve5_enrichment_supports_modern_record():
    respx.get("https://cve.circl.lu/api/cve/CVE-2026-1234").mock(
        return_value=httpx.Response(
            200,
            json={
                "cveMetadata": {"datePublished": "2026-01-01"},
                "containers": {
                    "cna": {
                        "descriptions": [
                            {"lang": "en", "value": "A buffer overflow affects Product."}
                        ],
                        "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": 9.8}}],
                        "affected": [{"product": "Product"}],
                        "references": [{"url": "https://vendor.test/advisory"}],
                    }
                },
            },
        )
    )
    result = await CIRCLCVEProvider().lookup(IOC(value="CVE-2026-1234", type=IOCType.CVE))
    assert result.score == 98
    assert result.details["vulnerable_products"] == ["Product"]
    assert "buffer overflow" in result.summary


@respx.mock
async def test_missing_cve_score_is_unknown_not_clean():
    respx.get("https://cve.circl.lu/api/cve/CVE-2026-1234").mock(
        return_value=httpx.Response(200, json={"summary": "Unscored issue"})
    )
    result = await CIRCLCVEProvider().lookup(IOC(value="CVE-2026-1234", type=IOCType.CVE))
    assert result.malicious is None
