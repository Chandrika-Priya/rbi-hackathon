package com.thoughtworks.ondc.poc.pocwrapper.asr;

import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SpeechResponse {
    private String transcript;
}
