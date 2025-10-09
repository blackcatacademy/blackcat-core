<?php
// libs/PDFHelper.php
// Small wrapper to generate PDF from HTML. If mPDF (or other) is present in /libs/, it will use it.
// Fallback: returns HTML with filename .html (download).
class PDFHelper {
    // $html string, $outFileName (suggested), $download boolean (send to browser)
    public static function outputPdfFromHtml(string $html, string $outFileName = 'document.pdf', bool $download = true) {
        // if mPDF exists in libs
        if (class_exists('Mpdf\\Mpdf')) {
            try {
                $mpdf = new \Mpdf\Mpdf(['tempDir' => __DIR__ . '/../tmp']);
                $mpdf->WriteHTML($html);
                if ($download) {
                    $mpdf->Output($outFileName, 'D');
                } else {
                    $mpdf->Output();
                }
                return true;
            } catch (\Exception $e) {
                // fallthrough to HTML fallback
            }
        }
        // fallback: offer HTML download
        if (!headers_sent()) {
            header('Content-Type: text/html; charset=utf-8');
            header('Content-Disposition: attachment; filename="'.basename(pathinfo($outFileName, PATHINFO_FILENAME)).'.html"');
        }
        echo $html;
        return true;
    }
}