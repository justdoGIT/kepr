// cli_seal/qr.rs — a terminal QR code drawn with half-block characters
// (T4.10): each text row holds two module rows (`▀` top, `▄` bottom, `█`
// both, space neither), inside a 4-module quiet zone. Light modules are
// drawn as blocks so the code reads correctly on a dark terminal, like
// the share QR codes.

use qrcode::{Color, EcLevel, QrCode};

/// The quiet zone the QR specification asks for, in modules.
pub const QUIET: usize = 4;

/// `text` as a QR code (error correction M: survives a smudged printout).
pub fn render(text: &str) -> Result<String, String> {
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M)
        .map_err(|e| format!("cannot make a QR code: {e}"))?;
    let width = code.width();
    let colors = code.to_colors();
    let size = width + 2 * QUIET;
    // Light (true) outside the code, in the quiet zone.
    let light = |x: usize, y: usize| -> bool {
        if x < QUIET || y < QUIET || x >= QUIET + width || y >= QUIET + width {
            return true;
        }
        colors[(y - QUIET) * width + (x - QUIET)] == Color::Light
    };
    let mut out = String::with_capacity((size + 1) * size.div_ceil(2) * 3);
    for y in (0..size).step_by(2) {
        for x in 0..size {
            let top = light(x, y);
            // An odd size leaves the last half-row in the quiet zone.
            let bottom = y + 1 >= size || light(x, y + 1);
            out.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_half_blocks_inside_a_quiet_zone() {
        let q = render("ABACUS ZOOM T-SHIRT YO-YO").unwrap();
        let lines: Vec<&str> = q.lines().collect();
        let width = lines[0].chars().count();
        assert!(lines.iter().all(|l| l.chars().count() == width));
        assert!(q.chars().all(|c| matches!(c, '█' | '▀' | '▄' | ' ' | '\n')));
        assert!(q.contains('▀') && q.contains('▄') && q.contains(' '));
        // Two module rows per text row.
        assert_eq!(lines.len(), width.div_ceil(2));
        // Quiet zone: the first two text rows (4 module rows) and the
        // first / last 4 columns of every row are light.
        assert!(lines[..2].iter().all(|l| l.chars().all(|c| c == '█')));
        for l in &lines {
            let c: Vec<char> = l.chars().collect();
            assert!(c[..QUIET].iter().all(|&c| c == '█'), "{l}");
            assert!(c[width - QUIET..].iter().all(|&c| c == '█'), "{l}");
        }
        // The finder pattern's dark border starts right after the zone.
        assert_ne!(lines[2].chars().nth(QUIET), Some('█'));
    }

    #[test]
    fn a_recovery_key_fits_a_terminal() {
        let words = kepr_core::recovery_words::encode(&[0xa5; 32]);
        let q = render(&words.as_str().to_uppercase()).unwrap();
        let width = q.lines().next().unwrap().chars().count();
        assert!(width <= 80, "{width} columns");
    }
}
