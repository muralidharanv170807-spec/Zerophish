"""
PhishGuard AI — API Routes
All API endpoints for phishing detection, history, and statistics.
"""

import logging

from fastapi import APIRouter, HTTPException, File, UploadFile
from pydantic import BaseModel, Field

from backend.app.detectors.url_detector import analyze_url, extract_url_features
from backend.app.detectors.message_detector import analyze_message
from backend.app.detectors.behavioral_detector import analyze_behavior
from backend.app.services.risk_aggregator import aggregate_risk, aggregate_screenshot_risk
from backend.app.ml.predictor import predictor
from backend.app.database.db import save_scan, get_history, get_statistics
from backend.app.services.image_scanner import (
    MAX_IMAGE_BYTES, OCRProcessingError, OCRUnavailableError, classify_payload, decode_image, decode_qr,
    extract_urls, ocr_image, validate_upload,
)

router = APIRouter()
logger = logging.getLogger(__name__)


async def _read_bounded_upload(file: UploadFile) -> bytes:
    """Read no more than the configured upload limit plus one sentinel byte."""
    contents = await file.read(MAX_IMAGE_BYTES + 1)
    validate_upload(file.content_type, contents)
    return contents


# --- Request/Response Models ---

class URLRequest(BaseModel):
    url: str = Field(..., min_length=3, description="URL to analyze")


class MessageRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=5,
        max_length=10_000,
        description="Message/email text to analyze (maximum 10,000 characters)",
    )


class AnalysisResponse(BaseModel):
    classification: str
    risk_score: int
    ml_probability: float
    indicators: list[str]
    recommendations: list[str]
    explanation: str
    score_breakdown: dict
    input_type: str
    scan_id: int
    scan_type: str | None = None
    qr_detected: bool | None = None
    decoded: bool | None = None
    payload_type: str | None = None
    payload: str | None = None
    ocr_detected: bool | None = None
    extracted_text: str | None = None
    extracted_urls: list[str] = Field(default_factory=list)
    diagnostics: dict | None = None


# --- Endpoints ---

@router.get("/health")
def health_check():
    """Health check endpoint."""
    model_status = predictor.get_status()
    return {
        "status": "healthy",
        "service": "PhishGuard AI",
        "version": "1.0.0",
        "ml_models": model_status,
    }


@router.post("/analyze/url", response_model=AnalysisResponse)
def analyze_url_endpoint(request: URLRequest):
    """
    Analyze a URL for phishing indicators.
    Pipeline: URL → feature extraction → URL analysis → ML prediction → risk aggregation → result
    """
    try:
        url = request.url.strip()

        # Step 1: URL feature extraction and heuristic analysis
        url_analysis = analyze_url(url)

        # Step 2: ML prediction using extracted features
        url_features = url_analysis["features"]
        ml_probability = predictor.predict_url(url_features)

        # Step 3: Behavioral analysis (on the URL itself as text)
        behavioral = analyze_behavior(url)

        # Step 4: Risk aggregation
        all_indicators = url_analysis["indicators"] + behavioral["indicators"]
        # Deduplicate indicators
        all_indicators = list(dict.fromkeys(all_indicators))

        result = aggregate_risk(
            ml_probability=ml_probability,
            url_indicator_score=url_analysis["indicator_score"],
            content_indicator_score=0,  # No content for pure URL analysis
            behavioral_score=behavioral["behavioral_score"],
            all_indicators=all_indicators,
            analysis_mode="url",
        )

        # Step 5: Save to database
        scan_id = save_scan(
            input_type="url",
            input_text=url,
            classification=result["classification"],
            risk_score=result["risk_score"],
            ml_probability=result["ml_probability"],
            indicators=result["indicators"],
            recommendations=result["recommendations"],
            explanation=result["explanation"],
        )

        return AnalysisResponse(
            classification=result["classification"],
            risk_score=result["risk_score"],
            ml_probability=result["ml_probability"],
            indicators=result["indicators"],
            recommendations=result["recommendations"],
            explanation=result["explanation"],
            score_breakdown=result["score_breakdown"],
            input_type="url",
            scan_id=scan_id,
        )

    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    except Exception:
        logger.exception("URL analysis failed")
        raise HTTPException(status_code=500, detail="Analysis failed. Please try again.") from None


@router.post("/analyze/message", response_model=AnalysisResponse)
def analyze_message_endpoint(request: MessageRequest):
    """
    Analyze a message/email for phishing indicators.
    Pipeline: Message → content analysis → behavioral analysis → ML prediction → risk aggregation → result
    """
    try:
        message = request.message.strip()

        # Step 1: Content/keyword analysis (also extracts and analyzes embedded URLs)
        content_analysis = analyze_message(message)

        # Step 2: Behavioral analysis
        behavioral = analyze_behavior(message)

        # Step 3: ML prediction on message text
        ml_probability = predictor.predict_message(message)

        # Step 4: Get URL indicator score from any embedded URLs
        url_indicator_score = 0
        if content_analysis["url_analysis"]:
            # Use the max score from analyzed URLs
            url_scores = [ua["indicator_score"] for ua in content_analysis["url_analysis"]]
            url_indicator_score = max(url_scores) if url_scores else 0

        # Step 5: Risk aggregation
        all_indicators = content_analysis["indicators"] + behavioral["indicators"]
        # Deduplicate indicators
        all_indicators = list(dict.fromkeys(all_indicators))

        result = aggregate_risk(
            ml_probability=ml_probability,
            url_indicator_score=url_indicator_score,
            content_indicator_score=content_analysis["indicator_score"],
            behavioral_score=behavioral["behavioral_score"],
            all_indicators=all_indicators,
            analysis_mode="message",
        )

        # Step 6: Save to database
        scan_id = save_scan(
            input_type="message",
            input_text=message,
            classification=result["classification"],
            risk_score=result["risk_score"],
            ml_probability=result["ml_probability"],
            indicators=result["indicators"],
            recommendations=result["recommendations"],
            explanation=result["explanation"],
        )

        return AnalysisResponse(
            classification=result["classification"],
            risk_score=result["risk_score"],
            ml_probability=result["ml_probability"],
            indicators=result["indicators"],
            recommendations=result["recommendations"],
            explanation=result["explanation"],
            score_breakdown=result["score_breakdown"],
            input_type="message",
            scan_id=scan_id,
        )

    except Exception:
        logger.exception("Message analysis failed")
        raise HTTPException(status_code=500, detail="Analysis failed. Please try again.") from None


@router.post("/analyze/qr", response_model=AnalysisResponse)
async def analyze_qr_endpoint(file: UploadFile = File(...)):
    try:
        contents = await _read_bounded_upload(file)
        image = decode_image(contents)
        qr_detected, payload = decode_qr(image)
        if not payload:
            message = (
                "A QR code was detected but its payload could not be decoded."
                if qr_detected else "No readable QR code was found."
            )
            raise HTTPException(status_code=422, detail={
                "success": False,
                "stage": "qr",
                "error": message,
            })

        payload_type = classify_payload(payload)
        urls = extract_urls(payload)
        if urls:
            extracted_url = urls[0]
            url_analysis = analyze_url(extracted_url)
            behavioral = analyze_behavior(extracted_url)
            ml_probability = predictor.predict_url(url_analysis["features"])
            indicators = ["QR code decoded", *url_analysis["indicators"], *behavioral["indicators"]]
            result = aggregate_risk(
                ml_probability, url_analysis["indicator_score"], 0,
                behavioral["behavioral_score"], list(dict.fromkeys(indicators)), "url"
            )
        else:
            content_analysis = analyze_message(payload)
            behavioral = analyze_behavior(payload)
            ml_probability = predictor.predict_message(payload)
            indicators = ["QR code decoded", *content_analysis["indicators"], *behavioral["indicators"]]
            result = aggregate_risk(
                ml_probability, 0, content_analysis["indicator_score"],
                behavioral["behavioral_score"], list(dict.fromkeys(indicators)), "message"
            )

        explanation = f"[QR Code Analysis] Decoded {payload_type} payload. " + result["explanation"]
        scan_id = save_scan("qr", payload, result["classification"], result["risk_score"], result["ml_probability"], result["indicators"], result["recommendations"], explanation)
        return AnalysisResponse(**{**result, "explanation": explanation}, input_type="qr", scan_id=scan_id, scan_type="qr", qr_detected=True, decoded=True, payload_type=payload_type, payload=payload, extracted_urls=urls)

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception:
        logger.exception("QR analysis failed")
        raise HTTPException(status_code=500, detail="QR analysis failed. Please try again.") from None


@router.post("/analyze/screenshot", response_model=AnalysisResponse)
async def analyze_screenshot_endpoint(file: UploadFile = File(...)):
    try:
        print("[SCREENSHOT] Request received")
        print(f"[SCREENSHOT] Content type: {file.content_type}")
        contents = await _read_bounded_upload(file)
        print(f"[SCREENSHOT] File size: {len(contents)} bytes")
        image = decode_image(contents)
        print("[SCREENSHOT] Image decoded")
        print("[SCREENSHOT] QR detection started")
        qr_detected, qr_payload = decode_qr(image)
        print(f"[SCREENSHOT] QR {'detected and decoded' if qr_payload else 'detected but not decoded' if qr_detected else 'not detected'}")
        ocr_text = ""
        if not qr_payload:
            print("[SCREENSHOT] OCR started")
            try:
                ocr_text = ocr_image(image)
            except OCRUnavailableError as exc:
                print(f"[SCREENSHOT] OCR unavailable: {exc}")
                raise HTTPException(status_code=503, detail={
                    "success": False,
                    "stage": "ocr",
                    "error": str(exc),
                }) from exc
            except OCRProcessingError as exc:
                raise HTTPException(status_code=422, detail={
                    "success": False,
                    "stage": "ocr",
                    "error": str(exc),
                }) from exc
            print("[SCREENSHOT] OCR completed")
        extracted_text = "\n".join(part for part in (ocr_text, qr_payload or "") if part).strip()
        if len(extracted_text) < 3:
            raise HTTPException(status_code=422, detail={
                "success": False,
                "stage": "ocr",
                "error": "No readable QR payload or text was found in the screenshot.",
            })

        urls = extract_urls(extracted_text)
        print(f"[SCREENSHOT] URLs extracted: {len(urls)}")
        print("[SCREENSHOT] Analysis started")
        text_for_message_rules = extracted_text
        for url in urls:
            text_for_message_rules = text_for_message_rules.replace(url, " ")
        content_analysis = analyze_message(text_for_message_rules)
        behavioral = analyze_behavior(extracted_text)
        message_probability = predictor.predict_message(extracted_text)
        url_indicator_score = 0
        url_model_probability = None
        url_indicators = []
        for url in urls[:5]:
            ua = analyze_url(url)
            url_indicator_score = max(url_indicator_score, ua["indicator_score"])
            url_indicators.extend(ua["indicators"])
            probability = predictor.predict_url(ua["features"])
            url_model_probability = max(url_model_probability or 0, probability)

        all_indicators = (["QR code decoded"] if qr_payload else []) + (["Screenshot OCR text analyzed"] if ocr_text else []) + content_analysis["indicators"] + behavioral["indicators"] + url_indicators
        all_indicators = list(dict.fromkeys(all_indicators))

        result = aggregate_screenshot_risk(
            message_probability=message_probability,
            url_probability=url_model_probability,
            url_indicator_score=url_indicator_score,
            content_indicator_score=content_analysis["indicator_score"],
            behavioral_score=behavioral["behavioral_score"],
            behavioral_indicator_count=behavioral["indicator_count"],
            all_indicators=all_indicators,
        )
        print(f"[SCREENSHOT] OCR text length: {len(extracted_text)}")
        print(f"[SCREENSHOT] Message model probability: {message_probability:.4f}")
        print(f"[SCREENSHOT] URL model probability: {url_model_probability}")
        print(f"[SCREENSHOT] Behavioral indicators: {behavioral['indicator_count']}")
        print(f"[SCREENSHOT] Final score: {result['risk_score']} ({result['classification']})")

        explanation_text = f"[Screenshot Analysis] Extracted {len(urls)} URL(s) and {len(extracted_text)} text characters. " + result["explanation"]

        scan_id = save_scan(
            input_type="screenshot",
            input_text=extracted_text[:500],
            classification=result["classification"],
            risk_score=result["risk_score"],
            ml_probability=result["ml_probability"],
            indicators=result["indicators"],
            recommendations=result["recommendations"],
            explanation=explanation_text,
        )

        print("[SCREENSHOT] Analysis completed")
        return AnalysisResponse(**{**result, "explanation": explanation_text}, input_type="screenshot", scan_id=scan_id, scan_type="screenshot", qr_detected=qr_detected, decoded=bool(qr_payload), ocr_detected=bool(ocr_text), extracted_text=extracted_text, extracted_urls=urls)

    except ValueError as e:
        raise HTTPException(status_code=400, detail={
            "success": False,
            "stage": "image_processing",
            "error": str(e),
        })
    except HTTPException:
        raise
    except Exception:
        logger.exception("Screenshot analysis failed")
        raise HTTPException(status_code=500, detail="Screenshot analysis failed. Please try again.") from None


@router.get("/history")
def get_history_endpoint(limit: int = 50):
    """Get scan history from the database."""
    try:
        history = get_history(limit=limit)
        return {"history": history, "count": len(history)}
    except Exception:
        logger.exception("History retrieval failed")
        raise HTTPException(status_code=500, detail="Unable to retrieve scan history.") from None


@router.get("/statistics")
def get_statistics_endpoint():
    """Get scan statistics from the database."""
    try:
        stats = get_statistics()
        return stats
    except Exception:
        logger.exception("Statistics retrieval failed")
        raise HTTPException(status_code=500, detail="Unable to retrieve scan statistics.") from None
