<?php

namespace App\Lib;

use Exception;

class Crypto
{
    public static function generateChallenge(): string
    {
        return base64_encode(random_bytes(32));
    }

    public static function verifyEd25519(string $publicKeyB64, string $messageB64, string $signatureB64): bool
    {
        if (!extension_loaded('sodium')) {
            Response::error('Sodium extension missing. Enable libsodium to verify signatures.', 500);
        }

        try {
            $publicKey = sodium_base642bin($publicKeyB64, SODIUM_BASE64_VARIANT_ORIGINAL);
            $signature = sodium_base642bin($signatureB64, SODIUM_BASE64_VARIANT_ORIGINAL);
            $message = base64_decode($messageB64, true);
        } catch (Exception $e) {
            return false;
        }

        if ($message === false) {
            return false;
        }

        return sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
    }
}
