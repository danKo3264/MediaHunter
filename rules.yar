rule CVE_2021_22204_ExifTool_RCE {
    meta:
        description = "Detects JPEG files with malicious metadata exploiting CVE-2021-22204"
        cve = "CVE-2021-22204"
        format = "JPEG"
        affected_product = "ExifTool"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2021-22204"
    strings:
        $jpg_header = { FF D8 FF E1 }
        $exif_block = "Exif" ascii
        $djvm = "DJVM" ascii
        $djvu = "DJVU" ascii
        $djvu_meta = "metadata" ascii
        $djvu_info = "INFO" ascii
    condition:
        filesize < 25MB and
        $jpg_header at 0 and
        $exif_block in (0..512) and
        for any i in (1..#exif_block) : (
            uint16(@exif_block[i] - 4) == 0xFFE1 and
            1 of ($djvm, $djvu, $djvu_meta, $djvu_info) in (@exif_block[i]..@exif_block[i] + 4096)
        )
}

rule CVE_2023_29340_AV1_RCE {
    meta:
        description = "Detects malformed AV1 exploiting CVE-2023-29340 (heap overflow via OBU header)"
        cve = "CVE-2023-29340"
        format = "AV1"
        affected_product = "Windows AV1 Extension"
        reference = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29340"
    strings:
        $av1_marker = "av01" ascii
        $obu_sequence = { 12 00 00 01 01 00 00 }
        $obu_overflow = { 10 08 FF FF FF FF 00 00 00 }
    condition:
        filesize < 100MB and
        $av1_marker at 0 and
        1 of ($obu_sequence, $obu_overflow) and
        @obu_sequence < filesize - 32
}

rule CVE_2023_29341_AV1_RCE {
    meta:
        description = "Detects malformed AV1 exploiting CVE-2023-29341 (heap overflow via OBU corruption)"
        cve = "CVE-2023-29341"
        format = "AV1"
        affected_product = "Windows AV1 Extension"
        reference = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29341"
    strings:
        $av1_marker = "av01" ascii
        $obu_start = { 10 08 01 00 00 01 00 00 }
        $obu_corrupt_size = { 12 FF FF FF FF }
    condition:
        filesize < 100MB and
        $av1_marker at 0 and
        1 of ($obu_start, $obu_corrupt_size) and
        @obu_corrupt_size < filesize - 32
}

rule CVE_2022_22003_Office_Graphics_RCE {
    meta:
        description = "Detects malformed EMF/WMF graphics in Office documents exploiting CVE-2022-22003"
        cve = "CVE-2022-22003"
        format = "EMF/WMF"
        affected_product = "Microsoft Office"
        reference = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22003"
    strings:
        $emf_header = { 01 00 00 00 20 45 4D 46 }
        $emf_size_overflow = { FF FF FF FF }
        $wmf_header = { D7 CD C6 9A 00 00 }
        $wmf_invalid_func = { 01 00 09 00 }
    condition:
        filesize < 50MB and (
            ($emf_header at 0 and $emf_size_overflow in (@emf_header..@emf_header + 64)) or
            ($wmf_header at 0 and $wmf_invalid_func in (@wmf_header..@wmf_header + 64))
        )
}

rule CVE_2022_2566_FFmpeg_MP4_RCE {
    meta:
        description = "Detects malformed MP4 files exploiting CVE-2022-2566 (ctts atom corruption)"
        cve = "CVE-2022-2566"
        format = "MP4"
        affected_product = "FFmpeg"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-2566"
        type = "RCE"
        severity = "high"
    strings:
        $ftyp_mp4 = "ftypmp42" ascii
        $moov_atom = { 6D 6F 6F 76 }
        $trak_atom = { 74 72 61 6B }
        $mdia_atom = { 6D 64 69 61 }
        $minf_atom = { 6D 69 6E 66 }
        $stbl_atom = { 73 74 62 6C }
        $ctts_atom = { 63 74 74 73 }
        $ctts_overflow = { FF FF FF FF 00 00 00 00 }
    condition:
        filesize < 100MB and
        $ftyp_mp4 at 4 and
        all of ($moov_atom, $trak_atom, $mdia_atom, $minf_atom, $stbl_atom) and
        for any i in (1..#ctts_atom) : (
            uint32(@ctts_atom[i] - 4) > 0xFFFF and
            $ctts_overflow in (@ctts_atom[i]..@ctts_atom[i] + 16)
        )
}

rule CVE_2023_5217_libvpx_RCE {
    meta:
        description = "Detects malformed WebM with VP8 payload exploiting CVE-2023-5217 (libvpx)"
        cve = "CVE-2023-5217"
        format = "WebM/VP8"
        affected_product = "libvpx (Chrome, Electron, Edge)"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-5217"
    strings:
        $ebml_header = { 1A 45 DF A3 }
        $segment = { 18 53 80 67 }
        $vp8_codec_id = "V_VP8" ascii
        $vp8_frame_start = { 9D 01 2A 80 02 5A }
        $vp8_payload = "VP8 " ascii
    condition:
        filesize < 100MB and
        $ebml_header at 0 and $segment and $vp8_codec_id and
        uint16(@vp8_frame_start + 3) > 2048 and
        1 of ($vp8_frame_start, $vp8_payload)
}

rule CVE_2022_23205_Photoshop_RCE {
    meta:
        description = "Detects malformed PSD files exploiting CVE-2022-23205"
        cve = "CVE-2022-23205"
        format = "PSD"
        affected_product = "Adobe Photoshop"
        reference = "https://helpx.adobe.com/security/products/photoshop/apsb22-07.html"
        type = "RCE"
        severity = "high"
    strings:
        $psd_header = { 38 42 50 53 }
        $reserved_block = { 00 01 00 00 00 00 00 00 }
        $oversized_len = { FF FF FF FF 38 42 50 53 }
        $img_data_marker = { 07 00 00 00 }
    condition:
        filesize < 50MB and
        $psd_header at 0 and
        @oversized_len > 64 and @oversized_len < filesize - 32 and
        2 of ($reserved_block, $oversized_len, $img_data_marker)
}

rule CVE_2023_4863_WebP_RCE {
    meta:
        description = "Detects WebP files exploiting CVE-2023-4863 via corrupted VP8X chunk (libwebp heap overflow)"
        cve = "CVE-2023-4863"
        format = "WebP"
        affected_product = "libwebp (Chrome, Edge, Firefox, etc.)"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-4863"
    strings:
        $webp_header = "RIFF" ascii
        $webp_format = "WEBP" ascii
        $vp8x_chunk_id = { 56 50 38 58 }
        $vp8x_overflag = { 56 50 38 58 0A 00 00 00 FF FF FF FF }
        $vp8x_framing_flag = { 56 50 38 58 0A 00 00 00 08 00 00 00 }
        $anml_chunk = "ANML" ascii
        $anmf_chunk = "ANMF" ascii
        $iccp_chunk = "ICCP" ascii
        $exif_chunk = "EXIF" ascii
    condition:
        filesize < 25MB and
        $webp_header at 0 and $webp_format at 8 and $vp8x_chunk_id at 12 and
        @vp8x_chunk_id < filesize - 16 and
        (1 of ($vp8x_overflag, $vp8x_framing_flag)) and
        1 of ($anml_chunk, $anmf_chunk, $iccp_chunk, $exif_chunk) in (@vp8x_chunk_id..filesize)
}

rule CVE_2023_28292_RAW_RCE {
    meta:
        description = "Detects malformed RAW image exploiting CVE-2023-28292 via corrupted TIFF in RAW"
        cve = "CVE-2023-28292"
        format = "RAW (NEF/CR2/DNG)"
        affected_product = "Windows Raw Image Extension"
        reference = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28292"
    strings:
        $tiff_le = { 49 49 2A 00 }
        $tiff_be = { 4D 4D 00 2A }
        $canon_tag = "Canon" ascii
        $exif_sig = "Exif" ascii
        $raw_start = { 00 00 00 08 00 00 00 08 00 00 }
    condition:
        filesize < 100MB and
        (uint16(0) == 0x4949 or uint16(0) == 0x4D4D) and
        1 of ($tiff_le, $tiff_be) and
        $exif_sig in (0..256) and
        1 of ($canon_tag, $raw_start) in (0..2048)
}

rule CVE_2022_30188_HEVC_RCE {
    meta:
        description = "Detects malformed HEVC video exploiting CVE-2022-30188"
        cve = "CVE-2022-30188"
        format = "HEVC"
        affected_product = "Windows HEVC Extension"
        reference = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30188"
    strings:
        $ftyp_hevc = "ftyphevc" ascii
        $nal_start = { 00 00 00 01 }
        $vps_header = { 00 00 00 01 40 01 0C 01 FF FF 01 60 }
        $slice_overflow = { 00 00 00 01 26 FF FF 00 20 00 00 00 00 00 00 }
        $slice_prefix = { 00 00 00 01 26 01 09 01 }
    condition:
        filesize < 100MB and
        $ftyp_hevc at 4 and
        $nal_start and
        (
            $vps_header or
            ($slice_overflow and @slice_overflow > 128) or
            $slice_prefix
        )
}

rule CVE_2022_44268_PNG_InfoLeak {
    meta:
        description = "Detects PNG files with malicious iCCP chunk triggering CVE-2022-44268"
        cve = "CVE-2022-44268"
        format = "PNG"
        affected_product = "ImageMagick, libpng"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-44268"
        type = "InfoLeak"
    strings:
        $png_header = { 89 50 4E 47 0D 0A 1A 0A }
        $iCCP_ascii = "iCCP" ascii
        $passwd = "/etc/passwd" ascii
        $cmd = "/bin/sh" ascii
        $dotdots = "../" ascii
        $fake_profile = { 00 00 00 0C 69 43 43 50 00 00 00 00 00 00 }
    condition:
        filesize < 20MB and
        $png_header at 0 and $iCCP_ascii and @iCCP_ascii < filesize - 32 and
        1 of ($passwd, $cmd, $dotdots, $fake_profile)
}

rule CVE_2023_47359_VLC_RCE {
    meta:
        description = "Detects malformed video container exploiting VLC RCE"
        cve = "CVE-2023-47359"
        format = "MKV/AVI"
        affected_product = "VLC Media Player"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2023-47359"
    strings:
        $mkv_header = { 1A 45 DF A3 }
        $segment_start = { 18 53 80 67 }
        $avi_riff = "RIFF" ascii
        $avi_list = "LIST" ascii
        $overflow_block = { FF FF FF FF }
    condition:
        filesize < 100MB and (
            ($mkv_header at 0 and $segment_start and $overflow_block in (@segment_start..filesize)) or
            ($avi_riff at 0 and $avi_list and $overflow_block in (@avi_list..filesize))
        )
}

rule CVE_2022_21844_HEVC_RCE {
    meta:
        description = "Detects malformed HEVC files exploiting CVE-2022-21844"
        cve = "CVE-2022-21844"
        format = "HEVC"
        affected_product = "Windows HEVC Codec Extension"
        reference = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21844"
    strings:
        $nal_start = { 00 00 00 01 }                       // NAL unit start
        $vps_nal = { 00 00 00 01 40 ?? ?? ?? ?? ?? ?? ?? } // VPS
        $sps_nal = { 00 00 00 01 42 ?? ?? ?? ?? ?? ?? ?? } // SPS
        $pps_nal = { 00 00 00 01 44 ?? ?? ?? ?? ?? ?? ?? } // PPS
        $overflow_seq = { 00 00 00 01 26 FF FF 00 20 00 00 00 00 00 00 }

        $ftyp_hevc = "ftyphevc" ascii
    condition:
        filesize < 15MB and
        $ftyp_hevc and $nal_start and 1 of ($vps_nal, $sps_nal, $pps_nal, $overflow_seq)
}

rule Acropalypse_PNG_Trailing_Leak {
    meta:
        description = "Detects PNG files with trailing data after IEND (aCropalypse vulnerability)"
        type = "Data leakage"
        affected_tool = "Windows Snipping Tool, Pixel screenshot API"
        reference = "https://acropalypse.app"
    strings:
        $png_header = { 89 50 4E 47 0D 0A 1A 0A }
        $iend_chunk = { 00 00 00 00 49 45 4E 44 AE 42 60 82 }

        $text_http = "http" ascii
        $text_snip = "Snip" ascii
        $jpeg_sig = { FF D8 FF }
        $possible_doc = "<!DOCTYPE html" ascii
        $zip_local_hdr = { 50 4B 03 04 }

    condition:
        $png_header at 0 and
        $iend_chunk and
        filesize > @iend_chunk + 12 and
        1 of ($text_http, $text_snip, $jpeg_sig, $possible_doc, $zip_local_hdr)
}

rule CVE_2023_28291_RAW_RCE {
    meta:
        description = "Detects malformed RAW image exploiting CVE-2023-28291 (EXIF heap overflow)"
        cve = "CVE-2023-28291"
        format = "RAW (TIFF)"
        affected_product = "Windows Raw Image Extension"
        reference = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28291"
        type = "RCE"
        severity = "high"
    strings:
        $tiff_le = { 49 49 2A 00 }
        $tiff_be = { 4D 4D 00 2A }
        $exif_marker = "Exif" ascii
        $overflow_offset = { FF FF FF FF }
    condition:
        filesize < 100MB and
        (uint16(0) == 0x4949 or uint16(0) == 0x4D4D) and
        1 of ($tiff_le, $tiff_be) and
        $exif_marker in (0..256) and
        $overflow_offset in (@exif_marker..@exif_marker + 1024)
}

rule CVE_2022_48434_VLC_GPU_UAF {
    meta:
        description = "Detects video container exploiting CVE-2022-48434 (VLC GPU decoding use-after-free)"
        cve = "CVE-2022-48434"
        format = "MKV"
        affected_product = "VLC Media Player"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2022-48434"
        type = "RCE"
        severity = "high"
    strings:
        $ebml_header = { 1A 45 DF A3 }
        $segment = { 18 53 80 67 }
        $tracks = { 16 54 AE 6B }
        $video_track = "V_MPEG4/ISO/AVC" ascii
        $gpu_string = "hardware_acceleration" ascii
        $vlc_config = "vlc::gpu::decoder" ascii
    condition:
        filesize < 100MB and
        $ebml_header at 0 and
        $segment and $tracks and $video_track and
        1 of ($gpu_string, $vlc_config)
}