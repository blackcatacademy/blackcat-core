<?php
// Minimal XLSX generator from 2D array using ZipArchive
class Excel {
    public static function array_to_xlsx(array $rows, string $outPath) {
        $zip = new ZipArchive();
        if ($zip->open($outPath, ZipArchive::OVERWRITE | ZipArchive::CREATE) !== true) throw new Exception('Cannot create xlsx');
        // [Content_Types].xml
        $zip->addFromString('[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8"?>' . "\n" .
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' .
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' .
            '<Default Extension="xml" ContentType="application/xml"/>' .
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' .
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' .
            '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>' .
            '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>' .
            '</Types>');
        // _rels/.rels
        $zip->addFromString('_rels/.rels', '<?xml version="1.0" encoding="UTF-8"?>' . "\n" .
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' .
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>' .
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>' .
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>' .
            '</Relationships>');
        // docProps/core.xml
        $zip->addFromString('docProps/core.xml', '<?xml version="1.0" encoding="UTF-8"?>' . "\n" .
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" ' .
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">' .
            '<dc:creator>Knihyodautorov</dc:creator><cp:lastModifiedBy>Knihyodautorov</cp:lastModifiedBy>' .
            '<dcterms:created xsi:type="dcterms:W3CDTF">' . date('c') . '</dcterms:created>' .
            '<dcterms:modified xsi:type="dcterms:W3CDTF">' . date('c') . '</dcterms:modified>' .
            '</cp:coreProperties>');
        // docProps/app.xml
        $zip->addFromString('docProps/app.xml', '<?xml version="1.0" encoding="UTF-8"?>' . "\n" .
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">' .
            '<Application>Knihyodautorov</Application></Properties>');
        // xl/workbook.xml
        $zip->addFromString('xl/workbook.xml', '<?xml version="1.0" encoding="UTF-8"?>' . "\n" .
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>');
        // xl/_rels/workbook.xml.rels
        $zip->addFromString('xl/_rels/workbook.xml.rels', '<?xml version="1.0" encoding="UTF-8"?>' . "\n" .
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' .
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>' .
            '</Relationships>');
        // xl/worksheets/sheet1.xml build rows
        $sheet = '<?xml version="1.0" encoding="UTF-8"?>' . "\n" .
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>';
        foreach ($rows as $ridx => $row) {
            $sheet .= '<row r="'.($ridx+1).'">';
            foreach ($row as $cidx => $cell) {
                $c = self::numToCol($cidx+1);
                $val = htmlspecialchars((string)$cell, ENT_QUOTES | ENT_XML1);
                $sheet .= '<c r="'.$c.($ridx+1).'" t="inlineStr"><is><t>'.$val.'</t></is></c>';
            }
            $sheet .= '</row>';
        }
        $sheet .= '</sheetData></worksheet>';
        $zip->addFromString('xl/worksheets/sheet1.xml', $sheet);
        $zip->close();
    }

    private static function numToCol($n) {
        $s = '';
        while($n>0) {
            $mod = ($n-1)%26;
            $s = chr(65+$mod) . $s;
            $n = (int)(($n-$mod)/26);
        }
        return $s;
    }
}