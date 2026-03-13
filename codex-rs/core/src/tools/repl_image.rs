use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use image::ImageFormat;

const DATA_URL_PREFIX: &str = "data:";
const SUPPORTED_IMAGE_FORMATS_MESSAGE: &str = "PNG, JPEG, GIF, or WebP";

pub(crate) fn validate_repl_image_data_url(
    image_url: &str,
    helper_name: &str,
) -> Result<(), String> {
    if !image_url
        .get(..DATA_URL_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(DATA_URL_PREFIX))
    {
        return Err(format!("{helper_name} only accepts data URLs"));
    }

    let Some(comma_index) = image_url.find(',') else {
        return Err(format!(
            "{helper_name} only accepts base64 data URLs for {SUPPORTED_IMAGE_FORMATS_MESSAGE} images"
        ));
    };
    let metadata = &image_url[..comma_index];
    let payload = &image_url[comma_index + 1..];
    let metadata_without_scheme = &metadata[DATA_URL_PREFIX.len()..];
    let mut metadata_parts = metadata_without_scheme.split(';');
    let mime_type = metadata_parts.next().unwrap_or_default();
    let has_base64_marker = metadata_parts.any(|part| part.eq_ignore_ascii_case("base64"));

    if !is_supported_image_mime_type(mime_type) {
        return Err(format!(
            "{helper_name} does not support image format `{mime_type}`; use {SUPPORTED_IMAGE_FORMATS_MESSAGE}"
        ));
    }
    if !has_base64_marker || payload.is_empty() {
        return Err(format!(
            "{helper_name} only accepts base64 data URLs for {SUPPORTED_IMAGE_FORMATS_MESSAGE} images"
        ));
    }

    let bytes = BASE64_STANDARD
        .decode(payload)
        .map_err(|_| format!("{helper_name} received invalid base64 image data"))?;
    let detected_format = image::guess_format(&bytes)
        .map_err(|_| format!("{helper_name} received invalid image data"))?;
    if !is_supported_image_format(detected_format) {
        return Err(format!(
            "{helper_name} does not support image format `{mime_type}`; use {SUPPORTED_IMAGE_FORMATS_MESSAGE}"
        ));
    }
    if !mime_matches_format(mime_type, detected_format) {
        return Err(format!(
            "{helper_name} declared image format `{mime_type}`, but the bytes decode as `{}`",
            format_to_mime_type(detected_format)
        ));
    }
    image::load_from_memory(&bytes)
        .map(|_| ())
        .map_err(|_| format!("{helper_name} received invalid image data"))
}

fn is_supported_image_mime_type(mime_type: &str) -> bool {
    matches!(
        mime_type.to_ascii_lowercase().as_str(),
        "image/png" | "image/jpeg" | "image/jpg" | "image/gif" | "image/webp"
    )
}

fn is_supported_image_format(format: ImageFormat) -> bool {
    matches!(
        format,
        ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::Gif | ImageFormat::WebP
    )
}

fn mime_matches_format(mime_type: &str, format: ImageFormat) -> bool {
    let normalized = mime_type.to_ascii_lowercase();
    match format {
        ImageFormat::Png => normalized == "image/png",
        ImageFormat::Jpeg => matches!(normalized.as_str(), "image/jpeg" | "image/jpg"),
        ImageFormat::Gif => normalized == "image/gif",
        ImageFormat::WebP => normalized == "image/webp",
        _ => false,
    }
}

fn format_to_mime_type(format: ImageFormat) -> &'static str {
    match format {
        ImageFormat::Png => "image/png",
        ImageFormat::Jpeg => "image/jpeg",
        ImageFormat::Gif => "image/gif",
        ImageFormat::WebP => "image/webp",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
pub(crate) const VALID_TEST_PNG_DATA_URL: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==";

#[cfg(test)]
pub(crate) const VALID_TEST_GIF_DATA_URL: &str =
    "data:image/gif;base64,R0lGODdhAQABAIAAAP///////ywAAAAAAQABAAACAkQBADs=";

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn validate_repl_image_data_url_accepts_supported_png() {
        assert_eq!(
            validate_repl_image_data_url(VALID_TEST_PNG_DATA_URL, "codex.emit_image"),
            Ok(())
        );
    }

    #[test]
    fn validate_repl_image_data_url_rejects_non_data_urls() {
        assert_eq!(
            validate_repl_image_data_url("https://example.com/image.png", "codex.emit_image"),
            Err("codex.emit_image only accepts data URLs".to_string())
        );
    }

    #[test]
    fn validate_repl_image_data_url_rejects_non_base64_payloads() {
        assert_eq!(
            validate_repl_image_data_url("data:image/png,abcd", "codex.emit_image"),
            Err(
                "codex.emit_image only accepts base64 data URLs for PNG, JPEG, GIF, or WebP images"
                    .to_string()
            )
        );
    }

    #[test]
    fn validate_repl_image_data_url_rejects_unsupported_svg_mime() {
        assert_eq!(
            validate_repl_image_data_url(
                "data:image/svg+xml;base64,PHN2Zy8+",
                "codex.emit_image"
            ),
            Err(
                "codex.emit_image does not support image format `image/svg+xml`; use PNG, JPEG, GIF, or WebP"
                    .to_string()
            )
        );
    }

    #[test]
    fn validate_repl_image_data_url_rejects_invalid_image_bytes() {
        assert_eq!(
            validate_repl_image_data_url("data:image/png;base64,AAA=", "codex.emit_image"),
            Err("codex.emit_image received invalid image data".to_string())
        );
    }

    #[test]
    fn validate_repl_image_data_url_rejects_mismatched_mime_type() {
        assert_eq!(
            validate_repl_image_data_url(VALID_TEST_GIF_DATA_URL, "codex.emit_image"),
            Ok(())
        );
        assert_eq!(
            validate_repl_image_data_url(
                "data:image/png;base64,R0lGODdhAQABAIAAAP///////ywAAAAAAQABAAACAkQBADs=",
                "codex.emit_image"
            ),
            Err(
                "codex.emit_image declared image format `image/png`, but the bytes decode as `image/gif`"
                    .to_string()
            )
        );
    }
}
