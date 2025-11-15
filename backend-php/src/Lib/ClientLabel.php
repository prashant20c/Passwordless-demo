<?php

namespace App\Lib;

class ClientLabel
{
    protected static array $osMap = [
        'windows nt' => 'Windows',
        'mac os x' => 'macOS',
        'iphone' => 'iOS',
        'ipad' => 'iPadOS',
        'android' => 'Android',
        'linux' => 'Linux',
    ];

    protected static array $browserMap = [
        'edg' => 'Microsoft Edge',
        'chrome' => 'Chrome',
        'safari' => 'Safari',
        'firefox' => 'Firefox',
        'fxios' => 'Firefox',
        'crios' => 'Chrome',
        'opr' => 'Opera',
        'opera' => 'Opera',
        'msie' => 'Internet Explorer',
        'trident' => 'Internet Explorer',
    ];

    public static function describe(?string $userAgent): string
    {
        $ua = strtolower($userAgent ?? '');
        if ($ua === '') {
            return 'Unknown device';
        }

        $os = self::detectOs($ua);
        $browser = self::detectBrowser($ua);

        if ($browser === 'Safari' && (str_contains($ua, 'iphone') || str_contains($ua, 'ipad'))) {
            $browser = 'Mobile Safari';
        }
        if ($browser === 'Chrome' && str_contains($ua, 'edg')) {
            $browser = 'Microsoft Edge';
        }

        if ($browser === 'Unknown browser' && $os === 'Unknown device') {
            return 'Unknown device';
        }
        if ($browser === 'Unknown browser') {
            return $os;
        }
        if ($os === 'Unknown device') {
            return $browser;
        }

        return sprintf('%s on %s', $browser, $os);
    }

    protected static function detectOs(string $ua): string
    {
        foreach (self::$osMap as $needle => $label) {
            if (str_contains($ua, $needle)) {
                return $label;
            }
        }
        if (str_contains($ua, 'macintosh')) {
            return 'macOS';
        }
        return 'Unknown device';
    }

    protected static function detectBrowser(string $ua): string
    {
        foreach (self::$browserMap as $needle => $label) {
            if (str_contains($ua, $needle)) {
                return $label;
            }
        }
        return 'Unknown browser';
    }
}
