import base64
from fastapi import HTTPException


def extract_text_from_image(file_bytes, media_type, ai_extract_function):
    """
    Wrapper for Claude Vision OCR.

    Parameters
    ----------
    file_bytes : bytes
        Raw image file bytes
    media_type : str
        Image MIME type (image/png, image/jpeg)
    ai_extract_function : function
        The Claude OCR function from app.py (_ai_extract_text)

    Returns
    -------
    str
        Extracted text from screenshot
    """

    try:
        img_b64 = base64.b64encode(file_bytes).decode("utf-8")

        extracted_text = ai_extract_function(img_b64, media_type)

        return extracted_text

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"OCR extraction failed: {str(e)}"
        )