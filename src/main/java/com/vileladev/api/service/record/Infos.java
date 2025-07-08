package com.vileladev.api.service.record;

import java.util.Date;

public record Infos(
        String signerName,
        Date signingTime,
        String documentName,
        String digestAlgorithm
) {
}
